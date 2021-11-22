const std = @import("std");

fn addTestToStep(b: *std.build.Builder, step: *std.build.Step, src: []const u8) void {
    const t = b.addTest(src);
    t.setBuildMode(.Debug);
    step.dependOn(&t.step);
}

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("interpreter", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.addPackagePath("zdf", "./src/zdf/src/main.zig");
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run tests");
    addTestToStep(b, test_step, "src/main.zig");
}
