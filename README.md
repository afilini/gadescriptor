# gadescriptor

Create the descriptor representation of a GreenAddress/Blockstream Green wallet give its mnemonic.

**This software is provided for educational purposes only. Use at your own risk.**

**Many of the legacy/less common Green account types are not supported. Moreover, it requires typing in your mnemonic, which is something you might
not want to do if you are using an hardware wallet. Also, the Green server currently doesn't support generating addresses outside of the app. If you do so and notice some funds are missing in the Green app,
please contact their support to try to fix your account.**

If you have Cargo installed on your computer, run:

```
cargo install --git https://github.com/afilini/gadescriptor
```

to install the `gadescriptor` command.

Then run:

```
gadescriptor --help
```

for a list of the available options
