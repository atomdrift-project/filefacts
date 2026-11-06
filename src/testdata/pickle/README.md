# Pickle fixtures

| File | SHA-256 | What the tests assert |
|---|---|---|
| `torch-protocol2-float-tensor.pt` | `6b49e623416998a79895dfbcfeffd6e4c109101af1cef2a211ecccd96fb70eb3` | Identified as a PyTorch model (`src/fileid/tests/packages.rs`); its pickle globals are `collections.OrderedDict`, `torch.FloatStorage` and `torch._utils._rebuild_tensor_v2`, and the raw tensor storage that follows the pickles is not decoded as opcodes (`src/formats/pickle/tests.rs`) |

Not a specimen: one small float tensor, written by
`torch.save` in PyTorch's legacy (pre-zip, pickle protocol 2) format, which
stores the magic number, protocol version and system info as pickles ahead of
the raw storage bytes. The script and PyTorch version that wrote it are to be
documented.
