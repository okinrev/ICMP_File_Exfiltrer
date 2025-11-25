# File Exfiltration (ICMP)

Un projet pour exfiltrer des fichiers via le protocole ICMP sur des sockets RAW

## Installation

Dans le répertoire racine, lancer la commande make

## Usage

```
-m, --master
    run the binary as a master (server), it's the default value
-s, --slave <Master IP>
    run the binary as a slave (client)
-f, --file <file path>
    Only for slave: specified the data file
    Incompatible with -d, --directory
-d, --directory <directory path>
    Only for slave: specified a directory, each file in the specified
    directory must be extracted (not recursivly)
    Incompatible with -f, --file
```

## Contributing

Il faudrait encore vérifier l'intégrité des fichiers envoyés et surtout les crypter via  sha256.'

Pour voir les dernière avancées sur le projet, merci de consulter le répertoire "V2_XOR_HASH" 

## License

GNU Licence

## Credits

s/o http://manpagesfr.free.fr/man/man3/getaddrinfo.3.html qui a été le point de départ du projet, il fallait ensuite passer de UDP à ICMP
