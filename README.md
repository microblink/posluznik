# Posluznik

This tool is a replacement for `emrun`. It enables better monitoring of the emscripten app under test. It will stop early if an exception is thrown.

## Usage instructions

### Simple server mode

This tool can be used as a simple server just to sever all `.html` and `.wasm` files.

```
posluznik
```

Just calling `posluznik` will serve the current directory on port `6931`. You can specify the port with `-p` option.

Files can be served from subdirectories with following flags:

| Flag | Subdirectory |
|------|--------------|
| `-r` | `Release`    |
| `-d` | `DevRelease` |
| `-D` | `Debug`      |

This is useful when calling `posluznik` from a build directory of a multi-config ninja build.

The tool will listen to `stdio.html` and print out the messages to the console.

### Launch chrome mode

This tool can also launch chrome with `--launch-chrome` flag. This will launch a headless chrome instance, connect to it, serve the website and close the browser when the emscripten app is done. In case of a crash, `posluznik` will print out the stack trace and exit. The run will be restarted in case `chrome` crashes.

For example:

```
posluznik --launch-chrome -- SomeTest.html --gtest_filter=SomeTest.SomeTest
```

This command will run `SomeTest.html` with the associated `SomeTest.wasm` files. It will run the `SomeTest.SomeTest` test case and exit.

### Additional options

There are options for tuning the test such as disabling the same-origin policy, enabling chrome logging, etc...
Run `posluznik --help` for more information. (Or read `src/configuration.rs`)

Following environment variables can be used to configure the tool:

| Variable                    | Description                                           |
|-----------------------------|-------------------------------------------------------|
| `POSLUZNIK_CHROME_PATH`     | Path to chrome executable.                            |
| `POSLUZNIK_CHROME_LOGGING`  | Enable chrome logging.                                |
| `POSLUZNIK_CHROME_LOG_PATH` | Path to the directory where the logs will be written. |


## Conan package

This tool can be built as a conan package. It expects that the `cargo` conan dependency exists.