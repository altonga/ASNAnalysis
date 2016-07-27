'''
ASN Analysis

python asnanalysis.py -i top-1m.csv -a asnmapping.txt -o opasn -t 500
'''
import sys
import getopt
import os
from subprocess import check_output
import pandas as pd
import matplotlib.pyplot as plt

num_experiments = 10
dns_query = 'origin.asn.cymru.com'
dns_server = '8.8.8.8:53'
asn_sites = dict()


def get_asns(afile):
    '''
    Get list of ASNs and owners.
    '''
    endl = os.linesep
    with open(afile) as asnfile:
        lines = asnfile.readlines()
    asn_map = dict()
    for line in lines:
        asn_info = line.strip(endl).strip().split(' ')
        asn_map[asn_info[0]] = asn_info[1]
    return asn_map


def reverse_ip(ip):
    '''
    Reverse ip string for query to CMYRU service.
    '''
    parts = ip.split('.')
    rev_ip = ''
    if len(parts) != 4:
        return ''
    for part in reversed(parts):
        rev_ip = rev_ip + part + '.'
    return rev_ip


def get_asns_domain(domain_ips):
    '''
    Run dig to DNS service provided by Team CMYRU to convert IP to ASN.
    '''
    endl = os.linesep
    domain_asns = dict()
    for domain, ip_list in domain_ips.iteritems():
        print 'Domain: ' + domain
        for ip in ip_list:
            dns_string = reverse_ip(ip) + dns_query
            print 'DNS_String: ' + dns_string
            try:
                dig_output = check_output(['dig', dns_string, 'TXT'])
                pretty_dig_output = dig_output.split(endl)
                for line in pretty_dig_output:
                    if ';' not in line and line not in '':
                        start = line.find('IN TXT')
                        if (start != -1):
                            short = line[start+8:].strip('"')
                            print 'ASN: ' + short
                            asn_info = short.split('|')
                            parts = [x.strip(' ') for x in asn_info]
                            domain_asns.setdefault(domain, set()).add(parts[0])
                            asn_sites.setdefault(parts[0], set()).add(domain)
            except:
                print 'Exception in dig for ' + dns_string
    return domain_asns


def is_ip(ip):
    '''
    Check if the given string contains valid ip address.
    '''
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        i = int(part)
        if i < 0 or i > 255:
            return False
    return True


def get_ips(top_sites):
    '''
    Run dig and get all ips hosting a domain.
    '''
    endl = os.linesep
    domain_ips = dict()
    for (rank, domain) in top_sites:
        try:
            digOutput = check_output(['dig', domain, dns_server])
            prettyDigOutput = digOutput.split(endl)
            for line in prettyDigOutput:
                if 'IN	A	' in line and ';' not in line:
                    start = line.find('IN	A	')
                    ip = line[start+5:]
                    if is_ip(ip):
                        domain_ips.setdefault(domain, list()).append(ip)
        except:
            print 'Exception in dig for ' + domain
    return domain_ips


def get_top_sites(ifile, threshold):
    '''
    Get top threshold number of sites from the file containing
    top sites from Alexa.
    '''
    endl = os.linesep

    with open(ifile) as infile:
        top_sites = [tuple(next(infile).strip(endl).split(','))
                     for x in xrange(threshold)]

    return top_sites


def usage(pgm):
    '''Print usage message'''
    print 'Usage: %s -i <inputfile> -a <asnfile> -o <outputfile> ' \
          '-t <threshold>' % pgm


def main(argv):
    inputfile = ''
    asnfile = ''
    outputfile = ''
    threshold = 0

    '''
    Parse command line option

    * inputfile: csv file containing the alexa top 1M sites/domains
    * asnfile: txt file containing the mapping between asns and owners
    * outputfile: txt file containing output of cdn analysis, a csv file is
    *             also generated with same prefix showing averages
    * threshold: number of top sites/domains to consider
    '''
    try:
        opts, args = getopt.getopt(argv[1:],
                                   'hi:a:o:t:',
                                   ['ifile=', 'afile=', 'ofile=',
                                    'threshold='])
    except getopt.GetoptError:
        usage(argv[0])
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage(arg[0])
            sys.exit()
        elif opt in ('-i', '--ifile'):
            inputfile = arg
        elif opt in ('-a', '--afile'):
            asnfile = arg
        elif opt in ('-o', '--ofile'):
            outputfile = arg
        elif opt in ('-t', '--threshold'):
            threshold = int(arg)

    print 'Input file is ', inputfile
    print 'ASN file is ', asnfile
    print 'Output file is ', outputfile
    print 'Threshold is ', str(threshold), '\n'
    if inputfile == '' or asnfile == '' or outputfile == '' or threshold <= 0:
        usage(argv[0])
        sys.exit(2)
    asn_map = get_asns(asnfile)
    top_sites = get_top_sites(inputfile, threshold)

    domain_ips = get_ips(top_sites)
    domain_asns = get_asns_domain(domain_ips)
    asn_counts = dict()
    domain_counts = dict()
    with open(outputfile + '.txt', 'w') as ofile:
        for domain in domain_asns:
            asns = domain_asns[domain]
            asn_string = ''
            for asn in asns:
                asn_string = asn_string + ' ' + asn
            domain_counts[domain] = len(asns)
            ofile.write(domain + asn_string + '\n')

    print domain_asns
    print domain_counts
    dc = pd.DataFrame.from_dict(domain_counts, orient='index')
    dc.columns = ['ASNCount']
    print dc
    fig = plt.figure('Histogram of # of ASNs per site')
    fig.canvas.set_window_title('Histogram of # of ASNs per site')
    dc.hist()
    plt.savefig(outputfile+'_site_hist.png')
    with open(outputfile + '.csv', 'w') as ofile:
        for asn in asn_sites:
            domains = asn_sites[asn]
            domain_string = ''
            for domain in domains:
                domain_string = domain_string + ' ' + domain
            asn_counts[asn] = len(domains)
            ofile.write(asn + domain_string + '\n')

    print asn_sites
    print asn_counts
    ac = pd.DataFrame.from_dict(asn_counts, orient='index')
    ac.columns = ['SiteCount']
    print ac
    fig = plt.figure('Histogram of # of sites per ASN')
    fig.canvas.set_window_title('Histogram of # of sites per ASN')
    ac.hist(layout=(1, 1))
    plt.savefig(outputfile+'_asn_hist.png')


if __name__ == '__main__':
    main(sys.argv[:])
