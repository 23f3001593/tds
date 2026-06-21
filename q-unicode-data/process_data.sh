#!/bin/bash

# 0. Download the files (Replace <URL> with the actual links)
# wget -qO data1.csv "<URL_1>"
# wget -qO data2.csv "<URL_2>"
# wget -qO data3.txt "<URL_3>"

# Process the files and calculate the sum
(
  # 1. Convert data1.csv from CP-1252 to UTF-8 and strip carriage returns
  iconv -f WINDOWS-1252 -t UTF-8 data1.csv | tr -d '\r'

  # 2. data2.csv is already UTF-8, just strip carriage returns
  cat data2.csv | tr -d '\r'

  # 3. Convert data3.txt from UTF-16 to UTF-8, strip carriage returns, 
  #    and convert tabs (\t) to commas (,)
  iconv -f UTF-16 -t UTF-8 data3.txt | tr -d '\r' | tr '\t' ','

) | awk -F',' '
  # If the first column matches any of the target symbols, add column 2 to our total
  $1 == "Œ" || $1 == "—" || $1 == "ˆ" { 
      sum += $2 
  }
  
  # Once all files are processed, print the final sum
  END { 
      print sum + 0 
  }
'
