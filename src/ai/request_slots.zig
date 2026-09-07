//! Shared provider-request quota across tests, turns, and summaries.

const std = @import("std");
const types = @import("types.zig");

pub const Limiter = struct {
    active: std.atomic.Value(usize) = .init(0),

    pub fn tryAcquire(self: *Limiter) bool {
        var current = self.active.load(.acquire);
        while (current < types.max_provider_requests) {
            if (self.active.cmpxchgWeak(current, current + 1, .acq_rel, .acquire)) |observed| {
                current = observed;
                continue;
            }
            return true;
        }
        return false;
    }

    pub fn release(self: *Limiter) void {
        const previous = self.active.fetchSub(1, .acq_rel);
        std.debug.assert(previous > 0);
    }

    pub fn count(self: *const Limiter) usize {
        return self.active.load(.acquire);
    }
};

test "provider request limiter admits exactly two slots" {
    var limiter = Limiter{};
    try std.testing.expect(limiter.tryAcquire());
    try std.testing.expect(limiter.tryAcquire());
    try std.testing.expect(!limiter.tryAcquire());
    limiter.release();
    try std.testing.expect(limiter.tryAcquire());
    limiter.release();
    limiter.release();
    try std.testing.expectEqual(@as(usize, 0), limiter.count());
}
