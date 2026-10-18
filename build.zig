const std = @import("std");

/// NOTE(Zig 0.17): `Build.pathFromRoot` was removed. Equivalent helper.
fn pathFromRoot(b: *std.Build, sub_path: []const u8) []u8 {
    const root_path = b.root.root_dir.path orelse ".";
    return std.fs.path.resolve(b.allocator, &.{ root_path, sub_path }) catch @panic("OOM");
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sci_root = b.option([]const u8, "sci-root", "Path to the sci checkout") orelse "../sci";
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "plugin_root", pathFromRoot(b, "."));

    const plugin_api = b.createModule(.{
        .root_source_file = b.path("src/plugin_api.zig"),
        .target = target,
        .optimize = optimize,
    });

    const root_module = b.createModule(.{
        .root_source_file = b.path("src/plugin.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const http_client_module = b.createModule(.{
        .root_source_file = b.path("../sa_plugin_http_client/src/http_saasm_api.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const http_server_module = b.createModule(.{
        .root_source_file = b.path("../sa_plugin_http_server/src/http_saasm_api.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const sa_net_primitives = b.createModule(.{
        // NB: sci_root may be absolute (outside the build root), where
        // b.path() panics; cwd_relative supports absolute paths.
        .root_source_file = .{ .cwd_relative = b.pathJoin(&.{ sci_root, "src", "runtime", "sa_net_primitives.zig" }) },
        .target = target,
        .optimize = optimize,
    });

    const sa_http2 = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathJoin(&.{ sci_root, "src", "runtime", "sa_http2.zig" }) },
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const sio_module = b.createModule(.{
        .root_source_file = .{ .cwd_relative = b.pathJoin(&.{ sci_root, "src", "sa_io.zig" }) },
        .target = target,
        .optimize = optimize,
    });

    root_module.addImport("plugin_api", plugin_api);
    root_module.addImport("sio", sio_module);
    root_module.addImport("sa_http2", sa_http2);
    http_client_module.addImport("plugin_api", plugin_api);
    http_server_module.addImport("plugin_api", plugin_api);
    http_client_module.addImport("sa_net_primitives", sa_net_primitives);
    http_server_module.addImport("sa_net_primitives", sa_net_primitives);
    http_client_module.addImport("sio", sio_module);
    http_server_module.addImport("sio", sio_module);
    sa_http2.addImport("sio", sio_module);
    root_module.addImport("http_client", http_client_module);
    root_module.addImport("http_server", http_server_module);
    root_module.addOptions("build_options", build_options);

    const lib = b.addLibrary(.{
        .name = "node",
        .root_module = root_module,
        .linkage = .dynamic,
    });
    root_module.linkSystemLibrary("resolv", .{});
    root_module.linkSystemLibrary("dl", .{});

    b.installArtifact(lib);

    const main_tests = b.addTest(.{
        .root_module = root_module,
    });

    const test_module = b.createModule(.{
        .root_source_file = b.path("tests/plugin_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_module.addImport("node", root_module);
    test_module.addImport("plugin_api", plugin_api);
    test_module.addImport("sio", sio_module);

    const run_main_tests = b.addRunArtifact(main_tests);
    main_tests.root_module.linkSystemLibrary("dl", .{});

    const plugin_tests = b.addTest(.{
        .root_module = test_module,
    });
    plugin_tests.root_module.linkSystemLibrary("dl", .{});
    const run_plugin_tests = b.addRunArtifact(plugin_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&run_plugin_tests.step);
}
