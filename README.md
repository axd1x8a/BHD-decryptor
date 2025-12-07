# BHD Decrypter

Really frickin' fast decrypter for Elden Ring's (and maybe other games') BHD (ebl, dvdbnds, etc.) files, written in Rust.

## Usage

```sh
Usage: bhd-decrypter.exe [OPTIONS]

Options:
  -i, --input <INPUT>    Input directory containing encrypted .bhd files [default: .]
  -o, --output <OUTPUT>  Output directory for decrypted files [default: output]
  -k, --keys <KEYS>      Keys directory containing .pem files [default: keys]
  -h, --help             Print help
```

## Keys

You can get the keys by looking up "BEGIN PUBLIC KEY" in the Elden Ring executable, or just check [BinderKeys](https://github.com/JKAnderson/BinderKeys)

## How fast is it?

fast.

```sh
$ time ./target/release/decrypter.exe --input $ELDENRING_EXE/../
Loaded key: Data0
Loaded key: Data1
Loaded key: Data2
Loaded key: Data3
Loaded key: Debug
Loaded key: DLC
Loaded key: sd
Loaded key: sd_dlc02
Loaded 8 keys
Processing: "C:/Program Files (x86)/Steam/steamapps/common/ELDEN RING/Game/Data0.bhd"
Skipping sd.bhd (not found)
Processing: "C:/Program Files (x86)/Steam/steamapps/common/ELDEN RING/Game/Data1.bhd"
Skipping sd_dlc02.bhd (not found)
Processing: "C:/Program Files (x86)/Steam/steamapps/common/ELDEN RING/Game/Data2.bhd"
Processing: "C:/Program Files (x86)/Steam/steamapps/common/ELDEN RING/Game/Data3.bhd"
Processing: "C:/Program Files (x86)/Steam/steamapps/common/ELDEN RING/Game/DLC.bhd"
  -> Valid BHD5 header
  -> Valid BHD5 header
  -> Valid BHD5 header
  -> Valid BHD5 header
  -> Valid BHD5 header
  -> Saved to "output\\Data3.bhd" (373575 bytes)
  -> Saved to "output\\DLC.bhd" (1388985 bytes)
  -> Saved to "output\\Data0.bhd" (1090890 bytes)
  -> Saved to "output\\Data2.bhd" (7196865 bytes)
  -> Saved to "output\\Data1.bhd" (6133260 bytes)
Done!
./target/release/bhd-decrypter.exe --input $ELDENRING  0.00s user 0.00s system 0% cpu 0.317 total
```

## Credits

- Our lord and savior [JKAnderson](https://github.com/JKAnderson) for BinderKeys, original BootBoost mod, and general modding wisdom
- [Dasaav-dsv](https://github.com/Dasaav-dsv) for pointing out some performance improvements
