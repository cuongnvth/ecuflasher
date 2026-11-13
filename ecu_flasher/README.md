# ECUFlasher

## Build

    build_all.bat            build the current version
    build_all.bat patch      1.0.0 -> 1.0.1, then build   (also: minor, major)

The version is stored in `app_version.py`. Every build gets a build number
(`build_number.txt`) and, when the folder is a git repository, the commit hash.
The result is shown in the app header, the window title, the
Windows file properties of `ECUFlasher.exe` and `dist\ECUFlasher\VERSION.txt`.
Running the app from source shows `(dev)` instead of a build number.

Other commands:

    python build_version.py --show
    python build_version.py --set 1.4.0

## Consecutive flashing

On the Flashing tab, `Consecutive runs` repeats the whole flash sequence N times and
`Delay between runs` is the wait before the next run. `Stop on first failure` ends
the series at the first failed run; untick it to continue anyway. Both settings are
saved with the configuration.
