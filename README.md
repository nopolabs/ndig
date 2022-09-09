# ndig

## usage
```shell
Usage: ndig [options] <domain>

Get DNS records using dig

Arguments:
  domain                 domain

Options:
  -V, --version          output the version number
  -t, --type [type...]   record type
  -s, --short [type...]  record type (short output)
  -h, --help             display help for command

Commands:
  help [command]         display help for command

Supported types: A, AAAA, ALIAS, CNAME, MX, NS, PTR, SOA, SRV, TXT, or ALL
```

## install
```shell
npm install
npm link
```
