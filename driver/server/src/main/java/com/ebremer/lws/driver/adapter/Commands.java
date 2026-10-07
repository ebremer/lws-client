// SPDX-License-Identifier: MIT
package com.ebremer.lws.driver.adapter;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Resolving an adapter's command line, and checking that what it names is there. */
public final class Commands {

    private Commands() {
    }

    /**
     * The executable to start: a relative path (one with a separator) resolves against the driver's home, and a
     * bare name is left to the system's search path.
     */
    public static String executable(String command, Path home) {
        if (command.indexOf('/') < 0 && command.indexOf(File.separatorChar) < 0) {
            return command;
        }
        Path path = Path.of(command);
        return path.isAbsolute() ? command : home.resolve(path).toAbsolutePath().normalize().toString();
    }

    /**
     * What the command line names that is missing: an executable that is not on the search path or not
     * executable, or a relative file argument (such as a jar or a script) that does not exist.
     */
    public static List<String> missing(List<String> command, Path home) {
        List<String> missing = new ArrayList<>();
        if (command.isEmpty()) {
            missing.add("(no command configured)");
            return missing;
        }
        String executable = executable(command.get(0), home);
        if (executable.equals(command.get(0)) && !Path.of(executable).isAbsolute()) {
            if (!onSearchPath(executable)) {
                missing.add(executable + " (not on PATH)");
            }
        } else if (!Files.isExecutable(Path.of(executable))) {
            missing.add(executable);
        }
        for (String argument : command.subList(1, command.size())) {
            if (!argument.startsWith("-") && argument.indexOf('/') > 0 && !Path.of(argument).isAbsolute()
                    && !Files.exists(home.resolve(argument))) {
                missing.add(home.resolve(argument).toAbsolutePath().normalize().toString());
            }
        }
        return missing;
    }

    private static boolean onSearchPath(String name) {
        String path = System.getenv("PATH");
        if (path == null) {
            return false;
        }
        for (String dir : path.split(File.pathSeparator)) {
            if (!dir.isEmpty() && Files.isExecutable(Path.of(dir, name))) {
                return true;
            }
        }
        return false;
    }
}
