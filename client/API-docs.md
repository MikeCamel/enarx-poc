# Enarx API description

This document describes the protocol between the various components
of the Enarx project:
- Enarx client
- Enarx keepmgr (Keep Manager)
- Enarx keepldr (Keep Loader)
- Enarx wasmldr (WebAssembly Loader)

The following components present APIs:
- keepmgr*: accessed by the client
- keepldr: accessed by the keepmgr and client (proxied by the keepmgr)
- wasmldr*: accessed by the client

The components with a * are RESTful.

## keepmgr

### /contracts
### /new_keep/[uuid]
### /keep/[uuid]

## wasmldr

### [tbd]/[uuid] 
(Over a UNIX domain socket)

### /payload
HTTPS
(todo: change to "/workload")