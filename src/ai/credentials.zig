//! Runtime-thread credential facade and native secure-entry boundary.

const std = @import("std");
const build_options = @import("build_options");

pub const service_name = "dev.oars.ai";
pub const max_secret_bytes: usize = 4096;
pub const max_account_bytes: usize = 256;
pub const max_prompt_title_bytes: usize = 128;
pub const max_prompt_message_bytes: usize = 1024;

pub const ConfigureStatus = enum { configured, canceled, denied, unavailable };
pub const Status = enum { configured, missing, denied, unavailable };

pub const Error = error{
    NotInstalled,
    WrongThread,
    InvalidProviderId,
    InvalidPromptText,
    InvalidSecret,
    SecretTooLarge,
    CredentialMissing,
    Denied,
    Unavailable,
};

pub const ServiceError = error{ Denied, Unavailable };

pub const Service = struct {
    context: *anyopaque,
    set_fn: *const fn (context: *anyopaque, service: []const u8, account: []const u8, secret: []const u8) ServiceError!void,
    get_fn: *const fn (context: *anyopaque, service: []const u8, account: []const u8, output: []u8) ServiceError!?usize,
    delete_fn: *const fn (context: *anyopaque, service: []const u8, account: []const u8) ServiceError!bool,

    fn set(self: Service, account: []const u8, secret: []const u8) ServiceError!void {
        return self.set_fn(self.context, service_name, account, secret);
    }

    fn get(self: Service, account: []const u8, output: []u8) ServiceError!?usize {
        return self.get_fn(self.context, service_name, account, output);
    }

    fn delete(self: Service, account: []const u8) ServiceError!bool {
        return self.delete_fn(self.context, service_name, account);
    }
};

pub const PromptResult = struct {
    status: ConfigureStatus,
    len: usize = 0,
};

pub const Prompt = struct {
    context: ?*anyopaque = null,
    invoke_fn: *const fn (context: ?*anyopaque, title: []const u8, message: []const u8, output: []u8) PromptResult,

    pub fn invoke(self: Prompt, title: []const u8, message: []const u8, output: []u8) PromptResult {
        return self.invoke_fn(self.context, title, message, output);
    }

    pub fn native() Prompt {
        return .{ .invoke_fn = nativePrompt };
    }
};

pub const SecretBuffer = struct {
    bytes: [max_secret_bytes]u8 = [_]u8{0} ** max_secret_bytes,
    len: usize = 0,

    pub fn slice(self: *const SecretBuffer) []const u8 {
        return self.bytes[0..self.len];
    }

    pub fn clear(self: *SecretBuffer) void {
        std.crypto.secureZero(u8, &self.bytes);
        self.len = 0;
    }
};

/// Installed by `App.start_fn` and cleared by `App.stop_fn`. The type-erased
/// service may contain the Runtime pointer, but a provider worker receives
/// only `SecretBuffer` and can never call this facade.
pub const Facade = struct {
    service: ?Service = null,
    runtime_thread: ?std.Thread.Id = null,
    accepting: bool = false,

    pub fn install(self: *Facade, service: Service) void {
        self.service = service;
        self.runtime_thread = std.Thread.getCurrentId();
        self.accepting = true;
    }

    pub fn clear(self: *Facade) void {
        self.accepting = false;
        self.service = null;
        self.runtime_thread = null;
    }

    fn resolve(self: *Facade) Error!Service {
        if (!self.accepting) return error.NotInstalled;
        const expected = self.runtime_thread orelse return error.NotInstalled;
        if (std.Thread.getCurrentId() != expected) return error.WrongThread;
        return self.service orelse error.NotInstalled;
    }

    pub fn configure(self: *Facade, prompt: Prompt, provider_id: []const u8, title: []const u8, message: []const u8) Error!ConfigureStatus {
        const service = try self.resolve();
        var account_buffer: [max_account_bytes]u8 = undefined;
        const account = try accountForProvider(provider_id, &account_buffer);
        if (!validPromptText(title, max_prompt_title_bytes) or !validPromptText(message, max_prompt_message_bytes)) return error.InvalidPromptText;

        var secret = SecretBuffer{};
        defer secret.clear();
        const prompted = prompt.invoke(title, message, &secret.bytes);
        switch (prompted.status) {
            .canceled, .denied, .unavailable => return prompted.status,
            .configured => {},
        }
        if (prompted.len > secret.bytes.len) return error.SecretTooLarge;
        secret.len = prompted.len;
        if (!validSecret(secret.slice())) return error.InvalidSecret;
        service.set(account, secret.slice()) catch |err| return switch (err) {
            error.Denied => .denied,
            error.Unavailable => .unavailable,
        };
        return .configured;
    }

    pub fn status(self: *Facade, provider_id: []const u8) Error!Status {
        const service = try self.resolve();
        var account_buffer: [max_account_bytes]u8 = undefined;
        const account = try accountForProvider(provider_id, &account_buffer);
        var secret = SecretBuffer{};
        defer secret.clear();
        const len = service.get(account, &secret.bytes) catch |err| return switch (err) {
            error.Denied => .denied,
            error.Unavailable => .unavailable,
        };
        if (len) |value| {
            if (value == 0 or value > secret.bytes.len) return error.InvalidSecret;
            secret.len = value;
            return if (validSecret(secret.slice())) .configured else error.InvalidSecret;
        }
        return .missing;
    }

    pub fn delete(self: *Facade, provider_id: []const u8) Error!Status {
        const service = try self.resolve();
        var account_buffer: [max_account_bytes]u8 = undefined;
        const account = try accountForProvider(provider_id, &account_buffer);
        _ = service.delete(account) catch |err| return switch (err) {
            error.Denied => .denied,
            error.Unavailable => .unavailable,
        };
        return .missing;
    }

    /// Copies one credential on the runtime thread for a provider job. The
    /// caller owns and must clear the returned buffer on every exit path.
    pub fn copySecret(self: *Facade, provider_id: []const u8) Error!SecretBuffer {
        const service = try self.resolve();
        var account_buffer: [max_account_bytes]u8 = undefined;
        const account = try accountForProvider(provider_id, &account_buffer);
        var secret = SecretBuffer{};
        errdefer secret.clear();
        const maybe_len = service.get(account, &secret.bytes) catch |err| return switch (err) {
            error.Denied => error.Denied,
            error.Unavailable => error.Unavailable,
        };
        const len = maybe_len orelse return error.CredentialMissing;
        if (len == 0 or len > secret.bytes.len) return error.InvalidSecret;
        secret.len = len;
        if (!validSecret(secret.slice())) return error.InvalidSecret;
        return secret;
    }
};

fn accountForProvider(provider_id: []const u8, output: []u8) Error![]const u8 {
    if (provider_id.len < 4 or provider_id.len > 64 or !std.mem.startsWith(u8, provider_id, "aip-")) return error.InvalidProviderId;
    for (provider_id[4..]) |ch| switch (ch) {
        'a'...'f', '0'...'9' => {},
        else => return error.InvalidProviderId,
    };
    return std.fmt.bufPrint(output, "ai:{s}", .{provider_id}) catch error.InvalidProviderId;
}

fn validPromptText(value: []const u8, max: usize) bool {
    return value.len > 0 and value.len <= max and std.unicode.utf8ValidateSlice(value) and std.mem.indexOfScalar(u8, value, 0) == null;
}

fn validSecret(value: []const u8) bool {
    return value.len > 0 and value.len <= max_secret_bytes and std.unicode.utf8ValidateSlice(value) and std.mem.indexOfScalar(u8, value, 0) == null;
}

const native_configured: c_int = 1;
const native_canceled: c_int = 0;
const native_denied: c_int = -1;
const native_too_large: c_int = -3;

extern fn oars_ai_secure_entry(
    title: [*]const u8,
    title_len: usize,
    message: [*]const u8,
    message_len: usize,
    secret: [*]u8,
    secret_cap: usize,
    secret_len: *usize,
) c_int;

fn nativePrompt(_: ?*anyopaque, title: []const u8, message: []const u8, output: []u8) PromptResult {
    if (comptime std.mem.eql(u8, build_options.platform, "null")) return .{ .status = .unavailable };
    var len: usize = 0;
    const result = oars_ai_secure_entry(title.ptr, title.len, message.ptr, message.len, output.ptr, output.len, &len);
    return switch (result) {
        native_configured => if (len <= output.len) .{ .status = .configured, .len = len } else .{ .status = .unavailable },
        native_canceled => .{ .status = .canceled },
        native_denied => .{ .status = .denied },
        native_too_large => .{ .status = .configured, .len = output.len + 1 },
        else => .{ .status = .unavailable },
    };
}

const Fake = struct {
    secret: [max_secret_bytes]u8 = [_]u8{0} ** max_secret_bytes,
    len: usize = 0,
    prompt_value: []const u8 = "sk-test-canary",
    prompt_status: ConfigureStatus = .configured,
    service_error: ?ServiceError = null,
    set_count: usize = 0,
    delete_count: usize = 0,

    fn set(context: *anyopaque, _: []const u8, _: []const u8, secret: []const u8) ServiceError!void {
        const self: *Fake = @ptrCast(@alignCast(context));
        if (self.service_error) |err| return err;
        @memcpy(self.secret[0..secret.len], secret);
        self.len = secret.len;
        self.set_count += 1;
    }

    fn get(context: *anyopaque, _: []const u8, _: []const u8, output: []u8) ServiceError!?usize {
        const self: *Fake = @ptrCast(@alignCast(context));
        if (self.service_error) |err| return err;
        if (self.len == 0) return null;
        @memcpy(output[0..self.len], self.secret[0..self.len]);
        return self.len;
    }

    fn delete(context: *anyopaque, _: []const u8, _: []const u8) ServiceError!bool {
        const self: *Fake = @ptrCast(@alignCast(context));
        if (self.service_error) |err| return err;
        const existed = self.len > 0;
        std.crypto.secureZero(u8, &self.secret);
        self.len = 0;
        self.delete_count += 1;
        return existed;
    }

    fn prompt(context: ?*anyopaque, _: []const u8, _: []const u8, output: []u8) PromptResult {
        const self: *Fake = @ptrCast(@alignCast(context.?));
        if (self.prompt_status != .configured) return .{ .status = self.prompt_status };
        if (self.prompt_value.len > output.len) return .{ .status = .configured, .len = output.len + 1 };
        @memcpy(output[0..self.prompt_value.len], self.prompt_value);
        return .{ .status = .configured, .len = self.prompt_value.len };
    }

    fn service(self: *Fake) Service {
        return .{ .context = self, .set_fn = set, .get_fn = get, .delete_fn = delete };
    }

    fn promptAdapter(self: *Fake) Prompt {
        return .{ .context = self, .invoke_fn = prompt };
    }
};

test "credential facade configures replaces reports and deletes without exposing a value" {
    var fake = Fake{};
    var facade = Facade{};
    facade.install(fake.service());
    defer facade.clear();
    const provider_id = "aip-0123456789abcdef0123456789abcdef";
    try std.testing.expectEqual(.missing, try facade.status(provider_id));
    try std.testing.expectEqual(.configured, try facade.configure(fake.promptAdapter(), provider_id, "Provider key", "OpenAI at https://api.openai.com"));
    try std.testing.expectEqual(@as(usize, 1), fake.set_count);
    try std.testing.expectEqual(.configured, try facade.status(provider_id));
    fake.prompt_value = "sk-replacement";
    try std.testing.expectEqual(.configured, try facade.configure(fake.promptAdapter(), provider_id, "Provider key", "Replace key"));
    try std.testing.expectEqualStrings("sk-replacement", fake.secret[0..fake.len]);
    var copied = try facade.copySecret(provider_id);
    try std.testing.expectEqualStrings("sk-replacement", copied.slice());
    copied.clear();
    try std.testing.expectEqual(.missing, try facade.delete(provider_id));
    try std.testing.expectEqual(.missing, try facade.status(provider_id));
}

test "credential facade has explicit cancel denied unavailable and bounds" {
    const provider_id = "aip-0123456789abcdef0123456789abcdef";
    var fake = Fake{};
    var facade = Facade{};
    facade.install(fake.service());
    defer facade.clear();
    fake.prompt_status = .canceled;
    try std.testing.expectEqual(.canceled, try facade.configure(fake.promptAdapter(), provider_id, "Provider key", "Canceled"));
    fake.prompt_status = .denied;
    try std.testing.expectEqual(.denied, try facade.configure(fake.promptAdapter(), provider_id, "Provider key", "Denied"));
    fake.prompt_status = .unavailable;
    try std.testing.expectEqual(.unavailable, try facade.configure(fake.promptAdapter(), provider_id, "Provider key", "Unavailable"));
    fake.prompt_status = .configured;
    var oversized: [max_secret_bytes + 1]u8 = [_]u8{'x'} ** (max_secret_bytes + 1);
    fake.prompt_value = &oversized;
    try std.testing.expectError(error.SecretTooLarge, facade.configure(fake.promptAdapter(), provider_id, "Provider key", "Too large"));
    fake.service_error = error.Denied;
    try std.testing.expectEqual(.denied, try facade.status(provider_id));
    fake.service_error = error.Unavailable;
    try std.testing.expectEqual(.unavailable, try facade.status(provider_id));
}

test "secret buffer clear overwrites full capacity" {
    var secret = SecretBuffer{};
    @memset(&secret.bytes, 0xa5);
    secret.len = secret.bytes.len;
    secret.clear();
    try std.testing.expectEqual(@as(usize, 0), secret.len);
    for (secret.bytes) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
}

fn wrongThreadStatus(facade: *Facade, result: *?Error) void {
    _ = facade.status("aip-0123456789abcdef0123456789abcdef") catch |err| {
        result.* = err;
        return;
    };
}

test "credential facade rejects another thread and use after stop" {
    var fake = Fake{};
    var facade = Facade{};
    facade.install(fake.service());
    var result: ?Error = null;
    const thread = try std.Thread.spawn(.{}, wrongThreadStatus, .{ &facade, &result });
    thread.join();
    try std.testing.expectEqual(error.WrongThread, result.?);
    facade.clear();
    try std.testing.expectError(error.NotInstalled, facade.status("aip-0123456789abcdef0123456789abcdef"));
}
