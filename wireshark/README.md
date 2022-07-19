Wireshark integration for Hop.
===

# Quickstart (Mac/Linux)

Assuming your Wireshark uses Lua 5.2 (check in `Help > About Wireshark`), install the lua 5.2 headers (e.g., `apt install liblua5.2-dev` on Debian-based systems)
* Otherwise, install the appropriate headers and update the `CCFLAGS` environment variable to have an `-I` to include whereever you installed the headers

If you're on Mac, set the `EXTENSION` environment variable to `dynlib`

Run `make install`
* This does some minor "magic" that may be slightly fragile with regard to setting the path to the shared library for the lua script to use---alternatively, one could do the following three steps
  1. Run `make libcompat.so` (or `make libcompat.dynlib` on Mac)
    * (Optionally move this file somewhere convenient)
  2. Add the line `local package_loc = /full/path/to/the/sharedlibrary.so` to the top of `hop.lua`
  3. Copy `hop.lua` into `$HOME/.local/lib/wireshark/plugins`
Launch Wireshark
Run `tcpdump -i any -w outputfile.pcap` to get a packet dump

# Setup (Windows)

1. Install [`tdm-gcc`](https://jmeubank.github.io/tdm-gcc/)[^1] and `make` from [Cygwin](https://www.cygwin.com/)
2. Install and compile the [Lua headers](https://www.lua.org/versions.html) corresponding to the version of Lua that your Wireshark uses (check in `Help > About Wireshark`)
3. Run `env CCFLAGS="-I/path/to/lua/install/include -DDLLEXPORT" LIBLUA="/path/to/lua/install/lib/liblua.a" EXTENSION="dll" INSTALL_DIR="C:/Users/YOUR USERNAME/AppData/Roaming/Wireshark/plugins" CC="gcc" make install` (with `/path/to/lua` set to the path to Lua from step 2)
  * This does some minor "magic" that may be slightly fragile with regard to setting the path to the shared library for the lua script to use---alternatively, one could do the following three steps
    1. Run `env <SAME FLAGS AS ABOVE (except INSTALL_DIR is optional)> make libcompat.dll`
      * (Optionally move this file somewhere convenient)
    2. Add the line `local package_loc = /full/path/to/the/sharedlibrary.dll` to the top of `hop.lua`
    3. Copy `hop.lua` into the wiresharks plugin location (`%APPDATA%/Wireshark/plugins`)
4. Launch Wireshark
  * If you get the error `Lua: Error during loading:`, the path name to your plugins directory and `attempt to call a nil value`, you can either follow the longer instructions in the bullet point to step three or edit `%APPDATA%/Wireshark/plugins/hop.lua`'s first line so that the path is a valid windows path (e.g., should start with `C:/` not `/cygdrive/c`)

# Running
When running Wireshark, you can secondary click on a HOP packet to edit the HOP decoding preferences to set the ephemeral keys. Both keys should be in the form of `[num num num]` (with the number of `num`s being equal to the length of the ephemeral key and each byte being separated by a space)

# TODO
Reliable Tube reassembly

Document other necessary steps on Windows?

Verify that the instructions are reasonably clear/correct for Mac/Linux

[^1]: `tdm-gcc` works while, e.g., `mingw` didn't seem to since `cgo` has a reliance on `pthreads`
