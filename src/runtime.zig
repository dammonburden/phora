const std = @import("std");

pub fn awakeMillis(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .awake).toMilliseconds();
}

pub fn realMillis(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .real).toMilliseconds();
}
