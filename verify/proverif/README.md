# proverif

`xfer.pv` is a symbolic model of the transfer protocol in `docs/SPEC.md` §7, with the network
fully under attacker control and one paired device compromised. It has not been run yet.

```
mkdir -p tool && cd tool
curl -sSfLO https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz
tar xzf proverif2.05.tar.gz && cd proverif2.05 && ./build -nointeract
./proverif ../../xfer.pv | grep -E 'RESULT|Error'
```

A proof here says the message flow has no logical flaw under idealised cryptography. It says
nothing about the implementation.
