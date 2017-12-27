## Id Generation
uniquid_id: uint8_t[32]
Uniq id is hex coded and constituted with
```
magic: 0x01
ip: char[4] (big endian)
timestamp ms: (timestamp in ms, only low 6byte)
pid: uint16_t (low 2byte in pid)
rand：uint16_t
rand: uint8_t
```
