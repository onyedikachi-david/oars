//! Versioned, secret-free provider metadata for Spec 11.

const std = @import("std");
const types = @import("types.zig");

pub const store_version: u32 = 1;
pub const max_name_bytes: usize = 96;
pub const max_base_url_bytes: usize = 512;
pub const max_model_bytes: usize = 256;
const max_store_bytes: usize = 1024 * 1024;
const max_receipts: usize = 128;

pub const Adapter = enum {
    openai_responses,
    openai_chat_completions,
};

pub const InstructionRole = enum { developer, system };
pub const StructuredOutput = enum { json_schema, json_object };
pub const TestStatus = enum { untested, passed, failed, stale };

pub const Draft = struct {
    id: ?[]const u8 = null,
    name: []const u8,
    adapter: Adapter,
    tool_mode: types.ToolMode = .structured_result,
    base_url: []const u8,
    model: []const u8,
    instruction_role: ?InstructionRole = null,
    structured_output: ?StructuredOutput = null,
};

pub const Public = struct {
    id: []const u8,
    name: []const u8,
    adapter: Adapter,
    tool_mode: types.ToolMode = .structured_result,
    base_url: []const u8,
    model: []const u8,
    instruction_role: ?InstructionRole = null,
    structured_output: ?StructuredOutput = null,
    revision: u64,
    tested_at_ms: ?i64 = null,
    test_status: TestStatus,

    pub fn deinit(self: *Public, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        allocator.free(self.base_url);
        allocator.free(self.model);
    }
};

pub fn deinitList(allocator: std.mem.Allocator, providers: []Public) void {
    for (providers) |*provider| provider.deinit(allocator);
    allocator.free(providers);
}

pub const Error = error{
    InvalidOperationId,
    InvalidId,
    InvalidName,
    InvalidBaseUrl,
    InvalidModel,
    InvalidCompatibility,
    InvalidTestStatus,
    NotFound,
    StaleRevision,
    OperationConflict,
    LimitExceeded,
    StoreCorrupt,
    StoreAccess,
    StoreQuarantineFailed,
    SerializeFailed,
    OutOfMemory,
};

const ReceiptKind = enum { save, delete };

const Receipt = struct {
    operation_id: []const u8,
    kind: ReceiptKind,
    request_sha256: []const u8,
    provider: ?Public = null,
};

const CredentialBinding = struct {
    provider_id: []const u8,
    origin: []const u8,
    generation: u64 = 1,
};

const Document = struct {
    version: u32 = store_version,
    providers: []Public = &.{},
    operations: []Receipt = &.{},
    credential_bindings: []CredentialBinding = &.{},
};

const LegacyCapabilities = struct {
    instruction_role: []const u8 = "system",
    streaming: bool = true,
    structured_output: bool = false,
};

const LegacyProvider = struct {
    adapter: []const u8,
    base_url: []const u8,
    model: []const u8,
    capabilities: LegacyCapabilities = .{},
    updated_at_ns: i64 = 0,
};

const Loaded = struct {
    parsed: std.json.Parsed(Document),
    content: ?[]u8,

    fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        self.parsed.deinit();
        if (self.content) |content| allocator.free(content);
    }
};

fn lockSpin(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

fn hasUnsafeText(value: []const u8) bool {
    if (!std.unicode.utf8ValidateSlice(value)) return true;
    for (value) |ch| if (ch < 0x20 or ch == 0x7f) return true;
    return false;
}

fn validId(value: []const u8) bool {
    if (value.len < 4 or value.len > 64 or !std.mem.startsWith(u8, value, "aip-")) return false;
    for (value[4..]) |ch| switch (ch) {
        'a'...'f', '0'...'9' => {},
        else => return false,
    };
    return true;
}

fn validPort(value: []const u8) bool {
    if (value.len == 0) return false;
    const port = std.fmt.parseInt(u16, value, 10) catch return false;
    return port != 0;
}

fn validHostname(value: []const u8) bool {
    if (value.len == 0 or value[0] == '.' or value[value.len - 1] == '.') return false;
    for (value) |ch| switch (ch) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '-' => {},
        else => return false,
    };
    return true;
}

fn unsafeEscapedPath(path: []const u8) bool {
    var i: usize = 0;
    while (i < path.len) : (i += 1) {
        if (path[i] != '%') continue;
        if (i + 2 >= path.len) return true;
        const hi = std.fmt.charToDigit(path[i + 1], 16) catch return true;
        const lo = std.fmt.charToDigit(path[i + 2], 16) catch return true;
        const decoded: u8 = @intCast((hi << 4) | lo);
        if (decoded == '.' or decoded == '/' or decoded == '\\' or decoded == '?' or decoded == '#') return true;
        i += 2;
    }
    return false;
}

/// Validates the API prefix and returns the same slice without trailing `/`.
/// Endpoint adapters append their own fixed path to this normalized prefix.
pub fn normalizeBaseUrl(value: []const u8) Error![]const u8 {
    const url = std.mem.trim(u8, value, " \t\r\n");
    if (url.len == 0 or url.len > max_base_url_bytes or hasUnsafeText(url)) return error.InvalidBaseUrl;
    if (std.mem.indexOfAny(u8, url, "?#\\") != null) return error.InvalidBaseUrl;

    const secure = std.mem.startsWith(u8, url, "https://");
    const loopback_http = std.mem.startsWith(u8, url, "http://");
    if (!secure and !loopback_http) return error.InvalidBaseUrl;
    const scheme_len: usize = if (secure) "https://".len else "http://".len;
    const rest = url[scheme_len..];
    if (rest.len == 0) return error.InvalidBaseUrl;
    const authority_end = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
    const authority = rest[0..authority_end];
    if (authority.len == 0 or std.mem.indexOfScalar(u8, authority, '@') != null) return error.InvalidBaseUrl;

    var host: []const u8 = undefined;
    if (authority[0] == '[') {
        const close = std.mem.indexOfScalar(u8, authority, ']') orelse return error.InvalidBaseUrl;
        host = authority[0 .. close + 1];
        if (close + 1 < authority.len) {
            if (authority[close + 1] != ':' or !validPort(authority[close + 2 ..])) return error.InvalidBaseUrl;
        }
        if (!std.mem.eql(u8, host, "[::1]") and !secure) return error.InvalidBaseUrl;
    } else {
        const colon = std.mem.lastIndexOfScalar(u8, authority, ':');
        if (colon) |index| {
            if (std.mem.indexOfScalar(u8, authority[0..index], ':') != null) return error.InvalidBaseUrl;
            host = authority[0..index];
            if (!validPort(authority[index + 1 ..])) return error.InvalidBaseUrl;
        } else host = authority;
        if (!validHostname(host)) return error.InvalidBaseUrl;
        if (!secure and !std.ascii.eqlIgnoreCase(host, "localhost") and !std.mem.eql(u8, host, "127.0.0.1")) return error.InvalidBaseUrl;
    }

    const path = rest[authority_end..];
    if (unsafeEscapedPath(path)) return error.InvalidBaseUrl;
    var segments = std.mem.splitScalar(u8, path, '/');
    while (segments.next()) |segment| {
        if (std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return error.InvalidBaseUrl;
        for (segment) |ch| if (ch == ' ' or ch == '\t') return error.InvalidBaseUrl;
    }

    var end = url.len;
    while (end > scheme_len and url[end - 1] == '/') end -= 1;
    if (end <= scheme_len or end < scheme_len + authority.len) return error.InvalidBaseUrl;
    return url[0..end];
}

pub fn validateDraft(draft: Draft) Error!void {
    if (draft.id) |id| if (!validId(id)) return error.InvalidId;
    const name = std.mem.trim(u8, draft.name, " \t\r\n");
    if (name.len == 0 or name.len > max_name_bytes or hasUnsafeText(name)) return error.InvalidName;
    _ = try normalizeBaseUrl(draft.base_url);
    const model = std.mem.trim(u8, draft.model, " \t\r\n");
    if (model.len == 0 or model.len > max_model_bytes or hasUnsafeText(model)) return error.InvalidModel;
    switch (draft.adapter) {
        .openai_responses => if (draft.instruction_role != null or draft.structured_output != null) return error.InvalidCompatibility,
        .openai_chat_completions => {
            if (draft.tool_mode == .structured_result) {
                if (draft.instruction_role == null or draft.structured_output == null) return error.InvalidCompatibility;
            } else {
                if (draft.structured_output != null) return error.InvalidCompatibility;
            }
        },
    }
}

fn clonePublic(allocator: std.mem.Allocator, provider: Public) !Public {
    const id = try allocator.dupe(u8, provider.id);
    errdefer allocator.free(id);
    const name = try allocator.dupe(u8, provider.name);
    errdefer allocator.free(name);
    const base_url = try allocator.dupe(u8, provider.base_url);
    errdefer allocator.free(base_url);
    const model = try allocator.dupe(u8, provider.model);
    return .{
        .id = id,
        .name = name,
        .adapter = provider.adapter,
        .tool_mode = provider.tool_mode,
        .base_url = base_url,
        .model = model,
        .instruction_role = provider.instruction_role,
        .structured_output = provider.structured_output,
        .revision = provider.revision,
        .tested_at_ms = provider.tested_at_ms,
        .test_status = provider.test_status,
    };
}

fn randomProviderId(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var bytes: [16]u8 = undefined;
    try std.Io.randomSecure(io, &bytes);
    const hex = std.fmt.bytesToHex(bytes, .lower);
    return std.fmt.allocPrint(allocator, "aip-{s}", .{hex});
}

fn hashSaveRequest(draft: Draft, expected_revision: ?u64, output: *[64]u8) []const u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("save\x00");
    if (draft.id) |id| hash.update(id);
    hash.update("\x00");
    hash.update(draft.name);
    hash.update("\x00");
    hash.update(@tagName(draft.adapter));
    hash.update("\x00");
    hash.update(@tagName(draft.tool_mode));
    hash.update("\x00");
    hash.update(draft.base_url);
    hash.update("\x00");
    hash.update(draft.model);
    hash.update("\x00");
    if (draft.instruction_role) |role| hash.update(@tagName(role));
    hash.update("\x00");
    if (draft.structured_output) |mode| hash.update(@tagName(mode));
    var rev: [8]u8 = undefined;
    std.mem.writeInt(u64, &rev, expected_revision orelse 0, .little);
    hash.update(&rev);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    output.* = std.fmt.bytesToHex(digest, .lower);
    return output;
}

fn hashDeleteRequest(provider_id: []const u8, expected_revision: u64, output: *[64]u8) []const u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("delete\x00");
    hash.update(provider_id);
    var rev: [8]u8 = undefined;
    std.mem.writeInt(u64, &rev, expected_revision, .little);
    hash.update(&rev);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    output.* = std.fmt.bytesToHex(digest, .lower);
    return output;
}

fn validDocument(document: Document) bool {
    if (document.version != store_version or document.providers.len > types.max_providers or document.operations.len > max_receipts) return false;
    for (document.providers, 0..) |provider, index| {
        if (!validId(provider.id) or provider.revision == 0) return false;
        validateDraft(.{
            .id = provider.id,
            .name = provider.name,
            .adapter = provider.adapter,
            .tool_mode = provider.tool_mode,
            .base_url = provider.base_url,
            .model = provider.model,
            .instruction_role = provider.instruction_role,
            .structured_output = provider.structured_output,
        }) catch return false;
        for (document.providers[index + 1 ..]) |other| if (std.mem.eql(u8, provider.id, other.id)) return false;
    }
    for (document.operations, 0..) |receipt, index| {
        if (!types.validOperationId(receipt.operation_id) or receipt.request_sha256.len != 64) return false;
        for (document.operations[index + 1 ..]) |other| if (std.mem.eql(u8, receipt.operation_id, other.operation_id)) return false;
    }
    for (document.credential_bindings, 0..) |binding, index| {
        if (!validId(binding.provider_id) or binding.generation == 0) return false;
        const normalized = normalizeBaseUrl(binding.origin) catch return false;
        if (!std.mem.eql(u8, normalized, binding.origin)) return false;
        for (document.credential_bindings[index + 1 ..]) |other| if (std.mem.eql(u8, binding.provider_id, other.provider_id)) return false;
    }
    return true;
}

fn syncParent(io: std.Io, path: []const u8) Error!void {
    const parent_path = std.fs.path.dirname(path) orelse ".";
    var parent = std.Io.Dir.cwd().openFile(io, parent_path, .{ .mode = .read_only, .allow_directory = true }) catch return error.StoreAccess;
    defer parent.close(io);
    parent.sync(io) catch return error.StoreAccess;
}

fn writeAtomically(allocator: std.mem.Allocator, io: std.Io, path: []const u8, bytes: []const u8) Error!void {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |dir| cwd.createDirPath(io, dir) catch return error.StoreAccess;
    var nonce: [12]u8 = undefined;
    std.Io.randomSecure(io, &nonce) catch return error.StoreAccess;
    const nonce_hex = std.fmt.bytesToHex(nonce, .lower);
    const tmp = std.fmt.allocPrint(allocator, "{s}.tmp-{s}", .{ path, nonce_hex }) catch return error.OutOfMemory;
    defer allocator.free(tmp);
    var renamed = false;
    defer if (!renamed) cwd.deleteFile(io, tmp) catch {};
    {
        var file = cwd.createFile(io, tmp, .{ .exclusive = true, .permissions = .fromMode(0o600) }) catch return error.StoreAccess;
        defer file.close(io);
        file.writeStreamingAll(io, bytes) catch return error.StoreAccess;
        file.sync(io) catch return error.StoreAccess;
    }
    std.Io.Dir.renameAbsolute(tmp, path, io) catch return error.StoreAccess;
    renamed = true;
    var file = cwd.openFile(io, path, .{ .mode = .read_write }) catch return error.StoreAccess;
    defer file.close(io);
    const stat = file.stat(io) catch return error.StoreAccess;
    if (stat.permissions.toMode() & 0o077 != 0) file.setPermissions(io, .fromMode(0o600)) catch return error.StoreAccess;
    file.sync(io) catch return error.StoreAccess;
    try syncParent(io, path);
}

fn quarantine(allocator: std.mem.Allocator, io: std.Io, path: []const u8) Error!void {
    var nonce: [8]u8 = undefined;
    std.Io.randomSecure(io, &nonce) catch return error.StoreQuarantineFailed;
    const nonce_hex = std.fmt.bytesToHex(nonce, .lower);
    const dir = std.fs.path.dirname(path) orelse ".";
    const base = std.fs.path.basename(path);
    const now = std.Io.Timestamp.now(io, .real).nanoseconds;
    const new_path = std.fmt.allocPrint(allocator, "{s}/{s}.corrupt-{d}-{s}", .{ dir, base, now, nonce_hex }) catch return error.OutOfMemory;
    defer allocator.free(new_path);
    std.Io.Dir.renameAbsolute(path, new_path, io) catch return error.StoreQuarantineFailed;
    syncParent(io, path) catch return error.StoreQuarantineFailed;
}

fn stringifyAndWrite(allocator: std.mem.Allocator, io: std.Io, path: []const u8, document: Document) Error!void {
    if (!validDocument(document)) return error.SerializeFailed;
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    std.json.Stringify.value(document, .{ .whitespace = .indent_2 }, &out.writer) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.SerializeFailed;
    try writeAtomically(allocator, io, path, out.writer.buffered());
}

pub const Store = struct {
    allocator: std.mem.Allocator = undefined,
    path: []const u8 = "",
    mutex: std.atomic.Mutex = .unlocked,

    fn emptyParsed(self: *Store) Error!std.json.Parsed(Document) {
        return std.json.parseFromSlice(Document, self.allocator, "{\"version\":1,\"providers\":[],\"operations\":[]}", .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.StoreCorrupt;
    }

    fn migrateLegacy(self: *Store, io: std.Io, content: []const u8) Error!std.json.Parsed(Document) {
        var legacy = std.json.parseFromSlice(LegacyProvider, self.allocator, content, .{}) catch return error.StoreCorrupt;
        defer legacy.deinit();
        const adapter: Adapter = if (std.mem.eql(u8, legacy.value.adapter, "openai_compatible") or std.mem.eql(u8, legacy.value.adapter, "custom")) .openai_chat_completions else return error.StoreCorrupt;
        const role: InstructionRole = if (std.mem.eql(u8, legacy.value.capabilities.instruction_role, "developer")) .developer else if (std.mem.eql(u8, legacy.value.capabilities.instruction_role, "system")) .system else return error.StoreCorrupt;
        const mode: StructuredOutput = if (legacy.value.capabilities.structured_output) .json_schema else .json_object;
        const name = std.mem.trim(u8, legacy.value.model, " \t\r\n");
        const id = randomProviderId(self.allocator, io) catch return error.OutOfMemory;
        defer self.allocator.free(id);
        const provider = Public{
            .id = id,
            .name = name,
            .adapter = adapter,
            .tool_mode = .structured_result,
            .base_url = try normalizeBaseUrl(legacy.value.base_url),
            .model = name,
            .instruction_role = role,
            .structured_output = mode,
            .revision = 1,
            .test_status = .stale,
        };
        try validateDraft(.{ .id = provider.id, .name = provider.name, .adapter = provider.adapter, .tool_mode = provider.tool_mode, .base_url = provider.base_url, .model = provider.model, .instruction_role = provider.instruction_role, .structured_output = provider.structured_output });
        var providers = [_]Public{provider};
        try stringifyAndWrite(self.allocator, io, self.path, .{ .providers = &providers });
        const migrated_bytes = std.Io.Dir.cwd().readFileAlloc(io, self.path, self.allocator, .limited(max_store_bytes)) catch return error.StoreAccess;
        defer self.allocator.free(migrated_bytes);
        return std.json.parseFromSlice(Document, self.allocator, migrated_bytes, .{ .allocate = .alloc_always }) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.StoreCorrupt;
    }

    fn loadLocked(self: *Store, io: std.Io) Error!Loaded {
        const content = std.Io.Dir.cwd().readFileAlloc(io, self.path, self.allocator, .limited(max_store_bytes)) catch |err| {
            if (err == error.FileNotFound) return .{ .parsed = try self.emptyParsed(), .content = null };
            return error.StoreAccess;
        };
        errdefer self.allocator.free(content);
        const parsed = std.json.parseFromSlice(Document, self.allocator, content, .{ .allocate = .alloc_always }) catch {
            const migrated = self.migrateLegacy(io, content) catch {
                quarantine(self.allocator, io, self.path) catch return error.StoreQuarantineFailed;
                return error.StoreCorrupt;
            };
            return .{ .parsed = migrated, .content = content };
        };
        if (!validDocument(parsed.value)) {
            parsed.deinit();
            quarantine(self.allocator, io, self.path) catch return error.StoreQuarantineFailed;
            return error.StoreCorrupt;
        }
        return .{ .parsed = parsed, .content = content };
    }

    pub fn list(self: *Store, io: std.Io) Error![]Public {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        const result = try self.allocator.alloc(Public, loaded.parsed.value.providers.len);
        errdefer self.allocator.free(result);
        var completed: usize = 0;
        errdefer for (result[0..completed]) |*provider| provider.deinit(self.allocator);
        for (loaded.parsed.value.providers, 0..) |provider, index| {
            result[index] = try clonePublic(self.allocator, provider);
            completed += 1;
        }
        return result;
    }

    pub fn get(self: *Store, io: std.Io, provider_id: []const u8) Error!Public {
        if (!validId(provider_id)) return error.InvalidId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value.providers) |provider| {
            if (std.mem.eql(u8, provider.id, provider_id)) return clonePublic(self.allocator, provider);
        }
        return error.NotFound;
    }

    pub fn save(self: *Store, io: std.Io, operation_id: []const u8, draft: Draft, expected_revision: ?u64) Error!Public {
        if (!types.validOperationId(operation_id)) return error.InvalidOperationId;
        try validateDraft(draft);
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        var request_buf: [64]u8 = undefined;
        const request_hash = hashSaveRequest(draft, expected_revision, &request_buf);
        for (loaded.parsed.value.operations) |receipt| {
            if (!std.mem.eql(u8, receipt.operation_id, operation_id)) continue;
            if (receipt.kind != .save or !std.mem.eql(u8, receipt.request_sha256, request_hash) or receipt.provider == null) return error.OperationConflict;
            return clonePublic(self.allocator, receipt.provider.?);
        }

        var generated_id: ?[]u8 = null;
        defer if (generated_id) |id| self.allocator.free(id);
        const id: []const u8 = if (draft.id) |value| value else blk: {
            if (expected_revision != null) return error.StaleRevision;
            var attempt: usize = 0;
            while (attempt < 8) : (attempt += 1) {
                const candidate = randomProviderId(self.allocator, io) catch return error.OutOfMemory;
                var duplicate = false;
                for (loaded.parsed.value.providers) |provider| if (std.mem.eql(u8, provider.id, candidate)) {
                    duplicate = true;
                    break;
                };
                if (!duplicate) {
                    generated_id = candidate;
                    break :blk candidate;
                }
                self.allocator.free(candidate);
            }
            return error.SerializeFailed;
        };

        var existing_index: ?usize = null;
        for (loaded.parsed.value.providers, 0..) |provider, index| if (std.mem.eql(u8, provider.id, id)) {
            existing_index = index;
            break;
        };
        if (draft.id != null and existing_index == null) return error.NotFound;
        if (existing_index) |index| {
            const expected = expected_revision orelse return error.StaleRevision;
            if (loaded.parsed.value.providers[index].revision != expected) return error.StaleRevision;
        } else if (loaded.parsed.value.providers.len >= types.max_providers) return error.LimitExceeded;

        const normalized = try normalizeBaseUrl(draft.base_url);
        const provider = Public{
            .id = id,
            .name = std.mem.trim(u8, draft.name, " \t\r\n"),
            .adapter = draft.adapter,
            .tool_mode = draft.tool_mode,
            .base_url = normalized,
            .model = std.mem.trim(u8, draft.model, " \t\r\n"),
            .instruction_role = draft.instruction_role,
            .structured_output = draft.structured_output,
            .revision = if (existing_index) |index| loaded.parsed.value.providers[index].revision + 1 else 1,
            .tested_at_ms = null,
            .test_status = if (existing_index == null) .untested else .stale,
        };

        var providers = std.ArrayList(Public).empty;
        defer providers.deinit(self.allocator);
        try providers.ensureTotalCapacity(self.allocator, loaded.parsed.value.providers.len + @intFromBool(existing_index == null));
        var replaced = false;
        for (loaded.parsed.value.providers) |current| {
            if (std.mem.eql(u8, current.id, id)) {
                providers.appendAssumeCapacity(provider);
                replaced = true;
            } else providers.appendAssumeCapacity(current);
        }
        if (!replaced) providers.appendAssumeCapacity(provider);

        var receipts = std.ArrayList(Receipt).empty;
        defer receipts.deinit(self.allocator);
        const retained_start = if (loaded.parsed.value.operations.len >= max_receipts) loaded.parsed.value.operations.len - (max_receipts - 1) else 0;
        try receipts.appendSlice(self.allocator, loaded.parsed.value.operations[retained_start..]);
        try receipts.append(self.allocator, .{ .operation_id = operation_id, .kind = .save, .request_sha256 = request_hash, .provider = provider });
        try stringifyAndWrite(self.allocator, io, self.path, .{ .providers = providers.items, .operations = receipts.items, .credential_bindings = loaded.parsed.value.credential_bindings });
        return clonePublic(self.allocator, provider);
    }

    pub fn delete(self: *Store, io: std.Io, operation_id: []const u8, provider_id: []const u8, expected_revision: u64) Error!void {
        if (!types.validOperationId(operation_id)) return error.InvalidOperationId;
        if (!validId(provider_id)) return error.InvalidId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        var request_buf: [64]u8 = undefined;
        const request_hash = hashDeleteRequest(provider_id, expected_revision, &request_buf);
        for (loaded.parsed.value.operations) |receipt| {
            if (!std.mem.eql(u8, receipt.operation_id, operation_id)) continue;
            if (receipt.kind != .delete or !std.mem.eql(u8, receipt.request_sha256, request_hash)) return error.OperationConflict;
            return;
        }
        var found = false;
        var providers = std.ArrayList(Public).empty;
        defer providers.deinit(self.allocator);
        try providers.ensureTotalCapacity(self.allocator, loaded.parsed.value.providers.len);
        for (loaded.parsed.value.providers) |provider| {
            if (std.mem.eql(u8, provider.id, provider_id)) {
                found = true;
                if (provider.revision != expected_revision) return error.StaleRevision;
            } else providers.appendAssumeCapacity(provider);
        }
        if (!found) return error.NotFound;
        var receipts = std.ArrayList(Receipt).empty;
        defer receipts.deinit(self.allocator);
        const retained_start = if (loaded.parsed.value.operations.len >= max_receipts) loaded.parsed.value.operations.len - (max_receipts - 1) else 0;
        try receipts.appendSlice(self.allocator, loaded.parsed.value.operations[retained_start..]);
        try receipts.append(self.allocator, .{ .operation_id = operation_id, .kind = .delete, .request_sha256 = request_hash });
        try stringifyAndWrite(self.allocator, io, self.path, .{ .providers = providers.items, .operations = receipts.items, .credential_bindings = loaded.parsed.value.credential_bindings });
    }

    /// Records the exact reviewed origin after a native credential write.
    /// A later provider URL edit leaves this binding unchanged, so admission
    /// rejects the old credential until the user configures it again.
    pub fn bindCredential(self: *Store, io: std.Io, provider_id: []const u8, origin: []const u8) Error!void {
        if (!validId(provider_id)) return error.InvalidId;
        const normalized = try normalizeBaseUrl(origin);
        if (!std.mem.eql(u8, normalized, origin)) return error.InvalidBaseUrl;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        var provider_found = false;
        for (loaded.parsed.value.providers) |current| if (std.mem.eql(u8, current.id, provider_id)) {
            provider_found = true;
            if (!std.mem.eql(u8, current.base_url, origin)) return error.StaleRevision;
            break;
        };
        if (!provider_found) return error.NotFound;
        var providers = std.ArrayList(Public).empty;
        defer providers.deinit(self.allocator);
        try providers.ensureTotalCapacity(self.allocator, loaded.parsed.value.providers.len);
        for (loaded.parsed.value.providers) |current| {
            if (std.mem.eql(u8, current.id, provider_id)) {
                var changed = current;
                changed.test_status = .stale;
                providers.appendAssumeCapacity(changed);
            } else providers.appendAssumeCapacity(current);
        }
        var bindings = std.ArrayList(CredentialBinding).empty;
        defer bindings.deinit(self.allocator);
        try bindings.ensureTotalCapacity(self.allocator, loaded.parsed.value.credential_bindings.len + 1);
        var replaced = false;
        for (loaded.parsed.value.credential_bindings) |binding| {
            if (std.mem.eql(u8, binding.provider_id, provider_id)) {
                bindings.appendAssumeCapacity(.{ .provider_id = provider_id, .origin = origin, .generation = binding.generation + 1 });
                replaced = true;
            } else bindings.appendAssumeCapacity(binding);
        }
        if (!replaced) bindings.appendAssumeCapacity(.{ .provider_id = provider_id, .origin = origin, .generation = 1 });
        try stringifyAndWrite(self.allocator, io, self.path, .{
            .providers = providers.items,
            .operations = loaded.parsed.value.operations,
            .credential_bindings = bindings.items,
        });
    }

    pub fn unbindCredential(self: *Store, io: std.Io, provider_id: []const u8) Error!void {
        if (!validId(provider_id)) return error.InvalidId;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        var bindings = std.ArrayList(CredentialBinding).empty;
        defer bindings.deinit(self.allocator);
        try bindings.ensureTotalCapacity(self.allocator, loaded.parsed.value.credential_bindings.len);
        for (loaded.parsed.value.credential_bindings) |binding| {
            if (!std.mem.eql(u8, binding.provider_id, provider_id)) bindings.appendAssumeCapacity(binding);
        }
        if (bindings.items.len == loaded.parsed.value.credential_bindings.len) return;
        var providers = std.ArrayList(Public).empty;
        defer providers.deinit(self.allocator);
        try providers.ensureTotalCapacity(self.allocator, loaded.parsed.value.providers.len);
        for (loaded.parsed.value.providers) |current| {
            if (std.mem.eql(u8, current.id, provider_id)) {
                var changed = current;
                changed.test_status = .stale;
                providers.appendAssumeCapacity(changed);
            } else providers.appendAssumeCapacity(current);
        }
        try stringifyAndWrite(self.allocator, io, self.path, .{
            .providers = providers.items,
            .operations = loaded.parsed.value.operations,
            .credential_bindings = bindings.items,
        });
    }

    pub fn credentialBound(self: *Store, io: std.Io, provider_id: []const u8, origin: []const u8) Error!bool {
        return (try self.credentialGeneration(io, provider_id, origin)) != null;
    }

    /// Returns the generation of the credential that is bound to this exact
    /// reviewed origin. Provider jobs freeze it before copying the secret.
    pub fn credentialGeneration(self: *Store, io: std.Io, provider_id: []const u8, origin: []const u8) Error!?u64 {
        if (!validId(provider_id)) return error.InvalidId;
        const normalized = try normalizeBaseUrl(origin);
        if (!std.mem.eql(u8, normalized, origin)) return error.InvalidBaseUrl;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        for (loaded.parsed.value.credential_bindings) |binding| {
            if (!std.mem.eql(u8, binding.provider_id, provider_id)) continue;
            return if (std.mem.eql(u8, binding.origin, origin)) binding.generation else null;
        }
        return null;
    }

    /// Persists only a test result for the exact provider and credential
    /// generations that made the request. An edit or credential replacement
    /// that races the request makes the completion stale instead of passing
    /// a different configuration.
    pub fn recordTestResult(self: *Store, io: std.Io, provider_id: []const u8, expected_revision: u64, expected_credential_generation: u64, status: TestStatus, tested_at_ms: i64) Error!Public {
        if (!validId(provider_id)) return error.InvalidId;
        if (status != .passed and status != .failed) return error.InvalidTestStatus;
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var loaded = try self.loadLocked(io);
        defer loaded.deinit(self.allocator);
        var index: ?usize = null;
        for (loaded.parsed.value.providers, 0..) |current, current_index| {
            if (!std.mem.eql(u8, current.id, provider_id)) continue;
            if (current.revision != expected_revision) return error.StaleRevision;
            index = current_index;
            break;
        }
        const provider_index = index orelse return error.NotFound;
        var binding_matches = false;
        for (loaded.parsed.value.credential_bindings) |binding| {
            if (std.mem.eql(u8, binding.provider_id, provider_id) and
                std.mem.eql(u8, binding.origin, loaded.parsed.value.providers[provider_index].base_url) and
                binding.generation == expected_credential_generation)
            {
                binding_matches = true;
                break;
            }
        }
        if (!binding_matches) return error.StaleRevision;
        var providers = std.ArrayList(Public).empty;
        defer providers.deinit(self.allocator);
        try providers.ensureTotalCapacity(self.allocator, loaded.parsed.value.providers.len);
        for (loaded.parsed.value.providers, 0..) |current, current_index| {
            if (current_index == provider_index) {
                var tested = current;
                tested.test_status = status;
                tested.tested_at_ms = tested_at_ms;
                providers.appendAssumeCapacity(tested);
            } else providers.appendAssumeCapacity(current);
        }
        try stringifyAndWrite(self.allocator, io, self.path, .{
            .providers = providers.items,
            .operations = loaded.parsed.value.operations,
            .credential_bindings = loaded.parsed.value.credential_bindings,
        });
        return clonePublic(self.allocator, providers.items[provider_index]);
    }
};

fn tempStore(allocator: std.mem.Allocator, io: std.Io, suffix: []const u8, dir_buffer: []u8, path_buffer: []u8) !struct { dir: []const u8, path: []const u8 } {
    const dir = try std.fmt.bufPrint(dir_buffer, "/tmp/oars-ai-provider-{s}-{d}", .{ suffix, std.Io.Timestamp.now(io, .real).nanoseconds });
    const path = try std.fmt.bufPrint(path_buffer, "{s}/ai.json", .{dir});
    _ = allocator;
    return .{ .dir = dir, .path = path };
}

test "provider URLs are normalized and reject unsafe authority and suffix data" {
    try std.testing.expectEqualStrings("https://api.openai.com/v1", try normalizeBaseUrl(" https://api.openai.com/v1/// "));
    try std.testing.expectEqualStrings("http://localhost:11434/v1", try normalizeBaseUrl("http://localhost:11434/v1/"));
    try std.testing.expectEqualStrings("http://[::1]:8000/v1", try normalizeBaseUrl("http://[::1]:8000/v1"));
    const invalid = [_][]const u8{
        "http://example.com/v1",
        "http://localhost.example/v1",
        "http://localhost./v1",
        "https://user:pass@example.com/v1",
        "https://example.com/v1?x=1",
        "https://example.com/v1#fragment",
        "https://example.com/v1/../admin",
        "https://example.com/v1/%2e%2e/admin",
        "https://example.com/v1\\responses",
        "https://example.com:0/v1",
        "https://",
    };
    for (invalid) |url| try std.testing.expectError(error.InvalidBaseUrl, normalizeBaseUrl(url));
}

test "adapter compatibility switches are explicit" {
    const responses = Draft{ .name = "OpenAI", .adapter = .openai_responses, .tool_mode = .native_function, .base_url = "https://api.openai.com/v1", .model = "gpt-5" };
    try validateDraft(responses);
    var bad_responses = responses;
    bad_responses.instruction_role = .developer;
    try std.testing.expectError(error.InvalidCompatibility, validateDraft(bad_responses));
    const chat = Draft{ .name = "Ollama", .adapter = .openai_chat_completions, .tool_mode = .structured_result, .base_url = "http://localhost:11434/v1", .model = "qwen3", .instruction_role = .system, .structured_output = .json_schema };
    try validateDraft(chat);
    var bad_chat = chat;
    bad_chat.structured_output = null;
    try std.testing.expectError(error.InvalidCompatibility, validateDraft(bad_chat));
    const chat_native = Draft{ .name = "Ollama Tools", .adapter = .openai_chat_completions, .tool_mode = .native_function, .base_url = "http://localhost:11434/v1", .model = "qwen3" };
    try validateDraft(chat_native);
    var bad_chat_native = chat_native;
    bad_chat_native.structured_output = .json_schema;
    try std.testing.expectError(error.InvalidCompatibility, validateDraft(bad_chat_native));
}

test "provider store is versioned, idempotent, atomic, owner-only, and revision checked" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buffer: [192]u8 = undefined;
    var path_buffer: [256]u8 = undefined;
    const temp = try tempStore(allocator, io, "core", &dir_buffer, &path_buffer);
    defer std.Io.Dir.cwd().deleteTree(io, temp.dir) catch {};
    var store = Store{ .allocator = allocator, .path = temp.path };
    const empty = try store.list(io);
    defer deinitList(allocator, empty);
    try std.testing.expectEqual(@as(usize, 0), empty.len);

    var created = try store.save(io, "provider-save-1", .{ .name = "OpenAI", .adapter = .openai_responses, .base_url = "https://api.openai.com/v1/", .model = "gpt-5" }, null);
    defer created.deinit(allocator);
    try std.testing.expect(validId(created.id));
    try std.testing.expectEqual(@as(u64, 1), created.revision);
    try std.testing.expectEqual(.untested, created.test_status);
    try std.testing.expectEqualStrings("https://api.openai.com/v1", created.base_url);
    try store.bindCredential(io, created.id, created.base_url);
    try std.testing.expect(try store.credentialBound(io, created.id, created.base_url));
    try std.testing.expectEqual(@as(?u64, 1), try store.credentialGeneration(io, created.id, created.base_url));
    var passed = try store.recordTestResult(io, created.id, created.revision, 1, .passed, 100);
    try std.testing.expectEqual(.passed, passed.test_status);
    passed.deinit(allocator);
    try store.bindCredential(io, created.id, created.base_url);
    var credential_changed = try store.get(io, created.id);
    try std.testing.expectEqual(.stale, credential_changed.test_status);
    credential_changed.deinit(allocator);
    try std.testing.expectError(error.StaleRevision, store.recordTestResult(io, created.id, created.revision, 1, .passed, 101));
    var retested = try store.recordTestResult(io, created.id, created.revision, 2, .passed, 102);
    try std.testing.expectEqual(.passed, retested.test_status);
    retested.deinit(allocator);

    var replay = try store.save(io, "provider-save-1", .{ .name = "OpenAI", .adapter = .openai_responses, .base_url = "https://api.openai.com/v1/", .model = "gpt-5" }, null);
    defer replay.deinit(allocator);
    try std.testing.expectEqualStrings(created.id, replay.id);
    try std.testing.expectEqual(created.revision, replay.revision);

    try std.testing.expectError(error.OperationConflict, store.save(io, "provider-save-1", .{ .name = "Different", .adapter = .openai_responses, .base_url = "https://api.openai.com/v1", .model = "gpt-5" }, null));
    try std.testing.expectError(error.StaleRevision, store.save(io, "provider-save-2", .{ .id = created.id, .name = "OpenAI", .adapter = .openai_responses, .base_url = "https://api.openai.com/v1", .model = "gpt-5.1" }, 99));

    var edited = try store.save(io, "provider-save-3", .{ .id = created.id, .name = "OpenAI production", .adapter = .openai_responses, .base_url = "https://api.openai.com/v1", .model = "gpt-5.1" }, 1);
    defer edited.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 2), edited.revision);
    try std.testing.expectEqual(.stale, edited.test_status);
    // A model-only edit leaves the credential bound to the same reviewed
    // origin, while the provider test state remains stale.
    try std.testing.expect(try store.credentialBound(io, edited.id, edited.base_url));
    try store.bindCredential(io, edited.id, edited.base_url);
    try std.testing.expect(try store.credentialBound(io, edited.id, edited.base_url));
    try store.unbindCredential(io, edited.id);
    try std.testing.expect(!(try store.credentialBound(io, edited.id, edited.base_url)));

    var file = try std.Io.Dir.cwd().openFile(io, temp.path, .{ .mode = .read_only });
    defer file.close(io);
    const stat = try file.stat(io);
    try std.testing.expectEqual(@as(u32, 0), stat.permissions.toMode() & 0o077);
    const content = try std.Io.Dir.cwd().readFileAlloc(io, temp.path, allocator, .limited(max_store_bytes));
    defer allocator.free(content);
    try std.testing.expect(std.mem.indexOf(u8, content, "api_key") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, content, "\"version\": 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, content, ".tmp-") == null);

    try store.delete(io, "provider-delete-1", edited.id, edited.revision);
    try store.delete(io, "provider-delete-1", edited.id, edited.revision);
    const after_delete = try store.list(io);
    defer deinitList(allocator, after_delete);
    try std.testing.expectEqual(@as(usize, 0), after_delete.len);
}

test "provider store enforces its cap and quarantines corruption" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buffer: [192]u8 = undefined;
    var path_buffer: [256]u8 = undefined;
    const temp = try tempStore(allocator, io, "cap", &dir_buffer, &path_buffer);
    defer std.Io.Dir.cwd().deleteTree(io, temp.dir) catch {};
    var store = Store{ .allocator = allocator, .path = temp.path };
    var created: [types.max_providers]Public = undefined;
    var count: usize = 0;
    defer for (created[0..count]) |*provider| provider.deinit(allocator);
    while (count < types.max_providers) : (count += 1) {
        var op_buffer: [32]u8 = undefined;
        var name_buffer: [32]u8 = undefined;
        const operation_id = try std.fmt.bufPrint(&op_buffer, "provider-cap-{d}", .{count});
        const name = try std.fmt.bufPrint(&name_buffer, "Provider {d}", .{count});
        created[count] = try store.save(io, operation_id, .{ .name = name, .adapter = .openai_responses, .base_url = "https://api.openai.com/v1", .model = "gpt-5" }, null);
    }
    try std.testing.expectError(error.LimitExceeded, store.save(io, "provider-cap-over", .{ .name = "Too many", .adapter = .openai_responses, .base_url = "https://api.openai.com/v1", .model = "gpt-5" }, null));

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = temp.path, .data = "{broken" });
    try std.testing.expectError(error.StoreCorrupt, store.list(io));
    const missing = std.Io.Dir.cwd().readFileAlloc(io, temp.path, allocator, .limited(64)) catch |err| err;
    try std.testing.expect(missing == error.FileNotFound);
}

test "valid legacy provider migrates once and becomes stale" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var dir_buffer: [192]u8 = undefined;
    var path_buffer: [256]u8 = undefined;
    const temp = try tempStore(allocator, io, "legacy", &dir_buffer, &path_buffer);
    defer std.Io.Dir.cwd().deleteTree(io, temp.dir) catch {};
    try std.Io.Dir.cwd().createDirPath(io, temp.dir);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = temp.path, .data = "{\"adapter\":\"openai_compatible\",\"base_url\":\"http://localhost:11434/v1\",\"model\":\"qwen3\",\"capabilities\":{\"instruction_role\":\"system\",\"streaming\":true,\"structured_output\":true},\"updated_at_ns\":1}" });
    var store = Store{ .allocator = allocator, .path = temp.path };
    const providers = try store.list(io);
    defer deinitList(allocator, providers);
    try std.testing.expectEqual(@as(usize, 1), providers.len);
    try std.testing.expectEqual(.openai_chat_completions, providers[0].adapter);
    try std.testing.expectEqual(.json_schema, providers[0].structured_output.?);
    try std.testing.expectEqual(.stale, providers[0].test_status);
    const second = try store.list(io);
    defer deinitList(allocator, second);
    try std.testing.expectEqualStrings(providers[0].id, second[0].id);
}
