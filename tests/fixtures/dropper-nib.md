# dropper.nib / dropper-keyed.nib

Both files are compiled from `dropper.xib`, a synthetic Cocoa window whose
File's Owner is a custom `DropperController` (Swift module `Dropper`) with a
`window` outlet and a `runPayload:` action on a "Run Payload" button. Nothing
executable is inside; the fixtures exercise the `nib.*` fact extraction.

`dropper.nib` is the `NIBArchive` layout (deployment target 10.13 and later).
`dropper-keyed.nib` is the `NSKeyedArchiver` binary-plist layout that older
deployment targets emit as `keyedobjects.nib` inside a nib bundle.

Regenerate with Xcode's ibtool:

```
ibtool --compile dropper.nib dropper.xib
ibtool --minimum-deployment-target 10.9 --compile bundle.nib dropper.xib
cp bundle.nib/keyedobjects.nib dropper-keyed.nib
```
