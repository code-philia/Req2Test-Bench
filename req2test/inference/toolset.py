"""The leaderboard's agent tool set: what an agent can run is the same on
every host (the engine's tool set "E", version 1).  Its shell is bash, and
outside the runtime pack it reaches no project toolchain (Go, PHP, Ruby, the
JDK, Maven, Gradle), no ripgrep and no Python that can import lxml or run
behave.  `masks` gives the bubblewrap options that hide them from a sandbox
that binds the host's system set at its own paths, as `run_agent`'s does.

A mask shadows a file with /dev/null and a directory with an empty
read-only tmpfs.  It changes the sandbox, never the host, and is resolved at
each launch, so a toolchain installed later is masked too.
"""
import glob
import os
import re

SHELL = "/bin/bash"
#: Project toolchains, masked alone or followed by a version of digits and
#: dots (`php8.3`, `ruby3.2`, `java17`) in each of `TOOL_DIRECTORIES`.
#: `/bin` and `/sbin` add names only where they are real directories; on a
#: merged-`/usr` host they resolve to `/usr/bin` and `/usr/sbin`.
MASKED_TOOLS = ("go", "gofmt", "php", "composer", "ruby", "gem", "bundle",
                "bundler", "irb", "java", "javac", "jshell", "mvn", "gradle",
                "rg")
TOOL_DIRECTORIES = ("/usr/bin", "/usr/sbin", "/usr/local/bin",
                    "/usr/local/sbin", "/bin", "/sbin")
#: Toolchain directories (glob patterns), masked when present.  Node is not:
#: no project uses it.
MASKED_TOOLCHAIN_DIRECTORIES = (
    "/usr/local/go", "/usr/lib/go", "/usr/lib/go-*", "/usr/lib/jvm",
    "/usr/lib/php", "/usr/lib/ruby", "/usr/share/maven", "/usr/share/gradle")
#: Python packages masked in the system package directories, so that no
#: Python outside the runtime pack can import lxml or run behave.
MASKED_PACKAGES = ("lxml", "behave")
MASKED_PACKAGE_DIRECTORIES = ("/usr/lib/python3/dist-packages",
                              "/usr/local/lib/python3.*/dist-packages")
#: Where the sandbox's system set puts the host's executables.
SYSTEM_ROOTS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/")


def masked_tool_pattern() -> str:
    """The regular expression a masked name matches in full."""
    return "(?:%s)[0-9.]*" % "|".join(map(re.escape, MASKED_TOOLS))


def directory_masks(paths) -> list:
    """An empty read-only tmpfs over each of the directories `paths`."""
    return [arg for path in paths for arg in ("--tmpfs", path, "--remount-ro", path)]


def masks() -> list:
    """The tool set's masks: the toolchain and package directories, then the
    files that the masked names in each bin directory resolve to.

    A name that links into a masked directory, or out of the system set (as
    through `/etc/alternatives`, which the sandbox does not bind), dangles in
    the sandbox and gets no mask: bubblewrap cannot make one on a link that
    dangles ("Can't create file at /usr/bin/java").
    """
    dirs = sorted({path for pattern in MASKED_TOOLCHAIN_DIRECTORIES
                   for path in glob.glob(pattern)})
    dirs += [os.path.join(directory, package)
             for pattern in MASKED_PACKAGE_DIRECTORIES
             for directory in sorted(glob.glob(pattern))
             for package in MASKED_PACKAGES]
    dirs = [path for path in dirs if os.path.isdir(path) and not os.path.islink(path)]
    masked, files = re.compile(masked_tool_pattern()), []
    for directory in TOOL_DIRECTORIES:
        if os.path.islink(directory) or not os.path.isdir(directory):
            continue        # /bin is /usr/bin on a merged-/usr host
        for name in sorted(filter(masked.fullmatch, os.listdir(directory))):
            path = os.path.join(directory, name)
            real = os.path.realpath(path)
            if os.path.islink(path) and (not real.startswith(SYSTEM_ROOTS) or any(
                    real.startswith(d + "/") for d in dirs)):
                continue
            if os.path.isfile(real) and real not in files:
                files.append(real)
    return directory_masks(dirs) + [arg for path in files
                                    for arg in ("--ro-bind", "/dev/null", path)]
