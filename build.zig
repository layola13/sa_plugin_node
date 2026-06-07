const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "plugin_root", b.pathFromRoot("."));

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

    root_module.addImport("plugin_api", plugin_api);
    http_client_module.addImport("plugin_api", plugin_api);
    http_server_module.addImport("plugin_api", plugin_api);
    root_module.addImport("http_client", http_client_module);
    root_module.addImport("http_server", http_server_module);
    root_module.addOptions("build_options", build_options);

    const lib = b.addLibrary(.{
        .name = "node",
        .root_module = root_module,
        .linkage = .dynamic,
    });
    lib.linkSystemLibrary("resolv");

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

    const run_main_tests = b.addRunArtifact(main_tests);

    const plugin_tests = b.addTest(.{
        .root_module = test_module,
    });
    const run_plugin_tests = b.addRunArtifact(plugin_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
    test_step.dependOn(&run_plugin_tests.step);
}
