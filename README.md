# ASNAnalysis
ASN Analysis of top 500 sites in Alexa

Command: `python asnanalysis.py -i top-1m.csv -a asnmapping.txt -o opasn -t 500`

I plotted two histograms.

1. opasn_asn_hist.png shows the number of sites per ASN. It is clear that many ASNs 
(i.e., over 200) have 1 site in the top 500. There is 1 ASN which has 59 sites.

2. opasn_site_hist.png shows the number of ASNs per site. It is clear that a majority
of sites use a single ASN, a few (<50 use 2), and hardly any use >3. None of the sites
use more than 6.


