const std = @import("std");
const c = @cImport({
    @cInclude("lmdb.h");
});

const Allocator = std.mem.Allocator;
const heap = std.heap;

pub const Error = error{
    INVAL,
    ACCES,
    NOMEM,
    NOENT,
    AGAIN,
    NOSPC,
    BUSY,
    INTR,
    PIPE,
    IO,

    MDB_KEYEXIST,
    MDB_NOTFOUND,
    MDB_PAGE_NOTFOUND,
    MDB_CORRUPTED,
    MDB_PANIC,
    MDB_VERSION_MISMATCH,
    MDB_INVALID,
    MDB_MAP_FULL,
    MDB_DBS_FULL,
    MDB_READERS_FULL,
    MDB_TLS_FULL,
    MDB_TXN_FULL,
    MDB_CURSOR_FULL,
    MDB_PAGE_FULL,
    MDB_MAP_RESIZED,
    MDB_INCOMPATIBLE,
    MDB_BAD_RSLOT,
    MDB_BAD_TXN,
    MDB_BAD_VALSIZE,
    MDB_BAD_DBI,

    MDB_UNKNOWN_ERROR,
};

fn throw(rc: c_int) Error!void {
    try switch (rc) {
        c.MDB_SUCCESS => {},
        c.MDB_KEYEXIST => Error.MDB_KEYEXIST,
        c.MDB_NOTFOUND => Error.MDB_NOTFOUND,
        c.MDB_PAGE_NOTFOUND => Error.MDB_PAGE_NOTFOUND,
        c.MDB_CORRUPTED => Error.MDB_CORRUPTED,
        c.MDB_PANIC => Error.MDB_PANIC,
        c.MDB_VERSION_MISMATCH => Error.MDB_VERSION_MISMATCH,
        c.MDB_INVALID => Error.MDB_INVALID,
        c.MDB_MAP_FULL => Error.MDB_MAP_FULL,
        c.MDB_DBS_FULL => Error.MDB_DBS_FULL,
        c.MDB_READERS_FULL => Error.MDB_READERS_FULL,
        c.MDB_TLS_FULL => Error.MDB_TLS_FULL,
        c.MDB_TXN_FULL => Error.MDB_TXN_FULL,
        c.MDB_CURSOR_FULL => Error.MDB_CURSOR_FULL,
        c.MDB_PAGE_FULL => Error.MDB_PAGE_FULL,
        c.MDB_MAP_RESIZED => Error.MDB_MAP_RESIZED,
        c.MDB_INCOMPATIBLE => Error.MDB_INCOMPATIBLE,
        c.MDB_BAD_RSLOT => Error.MDB_BAD_RSLOT,
        c.MDB_BAD_TXN => Error.MDB_BAD_TXN,
        c.MDB_BAD_VALSIZE => Error.MDB_BAD_VALSIZE,
        c.MDB_BAD_DBI => Error.MDB_BAD_DBI,
        @intFromEnum(std.posix.E.INVAL) => Error.INVAL,
        @intFromEnum(std.posix.E.ACCES) => Error.ACCES,
        @intFromEnum(std.posix.E.NOMEM) => Error.NOMEM,
        @intFromEnum(std.posix.E.NOENT) => Error.NOENT,
        @intFromEnum(std.posix.E.AGAIN) => Error.AGAIN,
        @intFromEnum(std.posix.E.NOSPC) => Error.NOSPC,
        @intFromEnum(std.posix.E.BUSY) => Error.BUSY,
        @intFromEnum(std.posix.E.INTR) => Error.INTR,
        @intFromEnum(std.posix.E.PIPE) => Error.PIPE,
        @intFromEnum(std.posix.E.IO) => Error.IO,
        else => Error.MDB_UNKNOWN_ERROR,
    };
}

inline fn sliceToVal(slice: []const u8) c.MDB_val {
    const ptr = @constCast(slice.ptr);
    const any_ptr: ?*anyopaque = @ptrCast(ptr);
    return .{
        .mv_size = slice.len,
        .mv_data = any_ptr,
    };
}

inline fn valToSlice(val: c.MDB_val) []const u8 {
    if (val.mv_data == null) return &[_]u8{};
    const raw_ptr = val.mv_data.?;
    const bytes_ptr: [*]u8 = @ptrCast(raw_ptr);
    return bytes_ptr[0..val.mv_size];
}

pub const Environment = struct {
    const Env = @This();

    ptr: *c.MDB_env,

    pub const Options = struct {
        map_size: usize = 0,
        max_dbs: u32 = 0,
        max_readers: u32 = 0,
        read_only: bool = false,
        write_map: bool = false,
        no_tls: bool = false,
        no_lock: bool = false,
        no_sync: bool = false,
        no_meta_sync: bool = false,
        map_async: bool = false,
        mode: c.mdb_mode_t = 0o664,
    };

    pub fn init(path: [:0]const u8, options: Options) !Environment {
        var env_ptr: ?*c.MDB_env = null;
        try throw(c.mdb_env_create(&env_ptr));
        errdefer c.mdb_env_close(env_ptr);

        if (options.map_size != 0) {
            try throw(c.mdb_env_set_mapsize(env_ptr, options.map_size));
        }
        if (options.max_dbs != 0) {
            try throw(c.mdb_env_set_maxdbs(env_ptr, options.max_dbs));
        }
        if (options.max_readers != 0) {
            try throw(c.mdb_env_set_maxreaders(env_ptr, options.max_readers));
        }

        var flags: c_uint = 0;
        if (options.read_only) flags |= c.MDB_RDONLY;
        if (options.write_map) flags |= c.MDB_WRITEMAP;
        if (options.no_tls) flags |= c.MDB_NOTLS;
        if (options.no_lock) flags |= c.MDB_NOLOCK;
        if (options.no_sync) flags |= c.MDB_NOSYNC;
        if (options.no_meta_sync) flags |= c.MDB_NOMETASYNC;
        if (options.map_async) flags |= c.MDB_MAPASYNC;

        try throw(c.mdb_env_open(env_ptr, path, flags, options.mode));
        return .{ .ptr = env_ptr.? };
    }

    pub fn deinit(self: Environment) void {
        c.mdb_env_close(self.ptr);
    }

    pub const Transaction = struct {
        const Self = @This();

        ptr: *c.MDB_txn,

        pub const Mode = enum { ReadOnly, ReadWrite };

        pub const Options = struct {
            mode: Mode = .ReadWrite,
            parent: ?*c.MDB_txn = null,
        };

        pub fn abort(self: Self) void {
            c.mdb_txn_abort(self.ptr);
        }

        pub fn commit(self: Self) !void {
            try throw(c.mdb_txn_commit(self.ptr));
        }

        pub fn database(self: Self, name: []const u8, options: Database.Options) !Database {
            var dbi: c.MDB_dbi = undefined;
            var flags: c_uint = 0;
            if (options.reverse_key) flags |= c.MDB_REVERSEKEY;
            if (options.integer_key) flags |= c.MDB_INTEGERKEY;
            if (options.create) flags |= c.MDB_CREATE;

            if (name.len == 0) {
                try throw(c.mdb_dbi_open(self.ptr, null, flags, &dbi));
            } else if (name.len <= 128) {
                var buf: [129]u8 = undefined;
                std.mem.copyForwards(u8, buf[0..name.len], name);
                buf[name.len] = 0;
                const name_ptr: [*:0]const u8 = @ptrCast(buf[0 .. name.len + 1].ptr);
                try throw(c.mdb_dbi_open(self.ptr, name_ptr, flags, &dbi));
            } else {
                const tmp = try heap.page_allocator.allocSentinel(u8, name.len, 0);
                defer heap.page_allocator.free(tmp);
                std.mem.copyForwards(u8, tmp[0..name.len], name);
                const name_ptr: [*:0]const u8 = @ptrCast(tmp.ptr);
                try throw(c.mdb_dbi_open(self.ptr, name_ptr, flags, &dbi));
            }

            return .{ .txn_ptr = self.ptr, .dbi = dbi };
        }
    };

    pub fn transaction(self: Env, options: Env.Transaction.Options) !Env.Transaction {
        var txn_ptr: ?*c.MDB_txn = null;
        var flags: c_uint = 0;
        switch (options.mode) {
            .ReadOnly => flags |= c.MDB_RDONLY,
            .ReadWrite => {},
        }
        try throw(c.mdb_txn_begin(self.ptr, options.parent, flags, &txn_ptr));
        return .{ .ptr = txn_ptr.? };
    }
};

pub const Database = struct {
    const Self = @This();

    txn_ptr: *c.MDB_txn,
    dbi: c.MDB_dbi,

    pub const Options = struct {
        reverse_key: bool = false,
        integer_key: bool = false,
        create: bool = false,
    };

    pub fn set(self: Self, key: []const u8, value: []const u8) !void {
        var k = sliceToVal(key);
        var v = sliceToVal(value);
        try throw(c.mdb_put(self.txn_ptr, self.dbi, &k, &v, 0));
    }

    pub fn get(self: Self, key: []const u8) !?[]const u8 {
        var k = sliceToVal(key);
        var v: c.MDB_val = .{ .mv_size = 0, .mv_data = null };
        const rc = c.mdb_get(self.txn_ptr, self.dbi, &k, &v);
        if (rc == c.MDB_NOTFOUND) return null;
        try throw(rc);
        return valToSlice(v);
    }

    pub fn delete(self: Self, key: []const u8) !void {
        var k = sliceToVal(key);
        try throw(c.mdb_del(self.txn_ptr, self.dbi, &k, null));
    }

    pub fn cursor(self: Self) !Cursor {
        var cursor_ptr: ?*c.MDB_cursor = null;
        try throw(c.mdb_cursor_open(self.txn_ptr, self.dbi, &cursor_ptr));
        return .{ .ptr = cursor_ptr.? };
    }
};

pub const Cursor = struct {
    const Self = @This();

    ptr: *c.MDB_cursor,

    pub fn deinit(self: Self) void {
        c.mdb_cursor_close(self.ptr);
    }

    pub fn getCurrentValue(self: Self) ![]const u8 {
        var v: c.MDB_val = undefined;
        try throw(c.mdb_cursor_get(self.ptr, null, &v, c.MDB_GET_CURRENT));
        return valToSlice(v);
    }

    pub fn goToNext(self: Self) !?[]const u8 {
        var k: c.MDB_val = undefined;
        const rc = c.mdb_cursor_get(self.ptr, &k, null, c.MDB_NEXT);
        if (rc == c.MDB_NOTFOUND) return null;
        try throw(rc);
        return valToSlice(k);
    }

    pub fn seek(self: Self, key: []const u8) !?[]const u8 {
        var k = sliceToVal(key);
        const rc = c.mdb_cursor_get(self.ptr, &k, null, c.MDB_SET_RANGE);
        if (rc == c.MDB_NOTFOUND) return null;
        try throw(rc);
        return valToSlice(k);
    }
};

pub const Transaction = Environment.Transaction;
