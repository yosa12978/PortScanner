# Port Scanner
```
Usage of portScanner:
      -addr string
            target address (default "scanme.nmap.org")
      -all
            the program will print both open and close ports
      -batch int
            number of ports that will be scanning at one time (default 2000)
      -json
            the program will serialize result in json and print it to stdout
      -ports string
            port scanning range (e.g. 80, 0-1023, 5000-6000) (default "0-1023")
      -timeout int
            time (in seconds) after processing connection will be terminated (default 75)
```

```
Example usage:
      portScanner --addr scanme.nmap.org --ports 0-65535
```