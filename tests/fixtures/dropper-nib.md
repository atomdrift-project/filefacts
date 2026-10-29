# dropper.nib / dropper-keyed.nib

Both files are compiled from `dropper.xib`, a synthetic Cocoa window whose
File's Owner is a custom `DropperController` (Swift module `Dropper`) with a
`window` outlet and a `runPayload:` action on a "Run Payload" button. Nothing
executable is inside; the fixtures exercise the `nib.*` fact extraction.
Written for this project (Apache-2.0).

| File | SHA-256 |
|---|---|
| `dropper.xib` | `ab29c7ca2cdc7a83dbb9be9d7ddd0cae3cbb46de001809bae978071a3e3641a9` |
| `dropper.nib` | `a811518c4420ebe791cd2194f21c56ce94dc57b6c32e113dbe554c06cbf8af01` |
| `dropper-keyed.nib` | `65ca0dee40bf0007025b8d7eeca496682a1244fea50dc80d7648bd945ef37132` |

`dropper.nib` is the `NIBArchive` layout (deployment target 10.13 and later).
`dropper-keyed.nib` is the `NSKeyedArchiver` binary-plist layout that older
deployment targets emit as `keyedobjects.nib` inside a nib bundle.

Regenerate with Xcode's ibtool:

```
ibtool --compile dropper.nib dropper.xib
ibtool --minimum-deployment-target 10.9 --compile bundle.nib dropper.xib
cp bundle.nib/keyedobjects.nib dropper-keyed.nib
```
