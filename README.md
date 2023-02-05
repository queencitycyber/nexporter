# nexporter

nexporter lets you export & explore Nessus professional scan data.

![image](https://user-images.githubusercontent.com/13237617/216835626-07c2a0d2-1527-42b0-a657-89c6329e9e23.png)

### Why

Nessus is alright when working with a handful of scans. But what if you have 50 different scans and wished to collate them all into a single database? That's what I tried to do here. 
The project uses `sqlitebiter` and `datasette` to transform all the `csv` files into a single `.sqlite` database and serve them locally in a browser for API integration, respectively. 

### Installation
Clone the repo and run:

```
git clone https://github.com/queencitycyber/nexporter
cd nexporter
python3 nexporter.py --help
```

For development, clone the repository and install it locally using Poetry.

```
git clone https://github.com/queencitycyber/nexporter
cd nexporter
poetry shell && poetry install
```


### Getting started

Point nexporter at your Nessus instance and it will export all scans as `csv` and transform them into a `sqlite` database
Optionally, pass the `--serve` argument and you'll have a local webserver to explore the data

### Example Usage

Connect to your Nessus instance and download all scans in `csv` format. Output results in `csv` directory

```
python3 nexporter.py -t https://127.0.0.1:8834 -u username -p password -o csv
```

If you don't want to pass credentials on the command line, source your username and password from environment variables:
```
export NESSUS_USER=USERNAME
export NESSUS_PASS=PASSWORD
python3 nexporter.py -t https://127.0.0.1:8834
```

<br>

### Thanks

- Shouts to [puzzlepeaches](https://github.com/puzzlepeaches) who helped on the hard stuff
- Thanks to [Simon Willison](https://github.com/simonw) for [datasette](https://github.com/simonw/datasette)
- Thanks to [Tsuyoshi Hombashi](https://github.com/thombashi) for [sqlitebiter](https://github.com/thombashi/sqlitebiter)
