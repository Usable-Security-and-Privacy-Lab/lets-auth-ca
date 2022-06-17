# Logging Using `zerolog`
For this program we use [zerolog](https://github.com/rs/zerolog) as our fully-featured logging framework. The program first sets up this logging using the SetUpLogging function from the util package. This uses a couple different command line flags to set up the logger. 
### `-log n`
This command line flag sets the logging level for the program. For different levels see zerolog documentation or run the ca with the --help flag
### `-path string`
This flag sets the file path that the logger will use as output. (This is not currently implemented)