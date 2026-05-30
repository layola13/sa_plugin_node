const std = @import("std");
const plugin_api = @import("plugin_api");
pub usingnamespace @import("node_saasm_api.zig");

const skills = [_]plugin_api.SkillSection{
    .{
        .name = "node-compat",
        .summary = "Node.js API compatibility layer exposed via dynamically loaded dynamic library.",
        .items = &.{
            "node os cpus, totalmem, freemem, homedir, tmpdir, platform, arch, release",
            "node process hrtime bigint, cpuUsage, memoryUsage, cwd, uptime, env, version",
            "node crypto randomBytes, hash, hmac, pbkdf2, randomUUID",
            "node events & readline (Phase 4: Slot Callback Register model)",
            "node net & dns (Phase 5: TCP Server/Client, DNS Resolve)",
            "node fs (Phase 6: Extended Read-only stat, readdir, lstat, exists)",
            "public SA interface files: node.sai and node.sal",
        },
    },
};

pub const plugin = plugin_api.Plugin{
    .name = "node",
    .skills = &skills,
};

pub const descriptor = plugin_api.PluginDescriptor{
    .abi_version = plugin_api.abi_version,
    .descriptor_size = @as(u32, @intCast(@sizeOf(plugin_api.PluginDescriptor))),
    .name = "node",
    .init = null,
    .prebuild = null,
    .postbuild = null,
    .handle_command = null,
    .skills_ptr = skills[0..].ptr,
    .skills_len = skills.len,
};

pub export const saasm_plugin_descriptor_v1: plugin_api.PluginDescriptor = descriptor;

pub export fn saasm_plugin_descriptor_v1_fn(out: *plugin_api.PluginDescriptor) callconv(.c) void {
    out.* = descriptor;
}
