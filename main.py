import shodan
import shodan.helpers as sh
import csv
from pathlib import Path
from collections import defaultdict

# Shodan API Key
# Enter your Shodan API key below
API_KEY = '<shodan_api_key>'
DEBUG = True
OUTPUT_DIR = Path('shodan_results/')
INPUT_FILE = 'shodan_data/shodan_input.json'

# This function parses the shodan data provided in shoda_data.
# Then prints the results to the console and writes it to a csv file
def parse_shodan_data():

    # create vuln dict
    vuln_dic = defaultdict(lambda: {"hosts": set(), "ports": set()})

    # Iterate over the provided input files
    for banner in sh.iterate_files(str(INPUT_FILE)):
        try:
            if 'vulns' in banner['opts'].keys():
                if len(banner['opts']['vulns']) > 0:
                    for vuln in banner['opts']['vulns']:
                        vuln_dic[vuln]["hosts"].add(banner['ip'])
                        vuln_dic[vuln]["ports"].add(banner['port'])
                    # print(banner['ip'])
                    # print(banner['hostnames'])
                    # print(banner['port'])
                    # print(f"{banner['opts']['vulns']}\t{banner['hostnames']}\t{banner['port']}")
                # print(banner['opts']['vulns'])
            # print(banner['port'])
            # print(banner['org'])
            # print(banner['domains'])

        except Exception as e:
            print('ERROR: Hit unexpected value in shodan data!')
            print(e)

    # sort vuln_dic by cve number
    vuln_dic = sorted(vuln_dic.items(), key=lambda x: x[0])
    print("vuln_dic: ", vuln_dic)


    # create csv file if it doesn't exist and open for write
    with open(OUTPUT_DIR/'parse_test.csv', mode="w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)

        # write column headers to csv and print to screen as well
        csv_writer.writerow(["vuln", "num_hosts", "unique_ports"])
        print("vuln\tnum_hosts\tunique_ports")

        # write each row of data to csv and print to screen
        for vuln, info in vuln_dic:
            num_hosts = len(info["hosts"])
            ports = "/".join(map(str, info["ports"]))
            csv_writer.writerow([vuln, num_hosts, ports])
            print(f"{vuln}\t{num_hosts}\t{ports}")


# This function runs a search on the provided query
def shodan_facet_search(shodan_api, search_query, n_results=5000, country_code='US', verbose=DEBUG):
    # The list of properties we want summary information on
    # Specify as a tuple, otherwise default number of results returned is 5
    FACETS = [
        ('http.title', n_results),
        ('port', n_results),
        ('vuln', n_results),
        ('domain', n_results),
        ('org', n_results)
    ]

    #initialize return variable. Required format!
    shodan_data = {
        'http.title': [],
        'port': [],
        'vuln': [],
        'org': [],
        'domain': []
    }

    try:
        # Add Country filter to query
        _query = f'{search_query} country:{country_code}'

        # Use the shodan_api.count() method because:
        # 	- It doesn't return overly detailed results and doesn't require a paid API plan
        # 	- It also runs faster than doing a search().
        res  = shodan_api.count(_query, facets=FACETS)

        # Parse results
        for facet in res['facets']:
            for value in res['facets'][facet]:
                facet_data = {'count': value['count'], 'value': value['value']}
                shodan_data[facet].append(facet_data)
                # print("facet: ", facet_data)

        # Return facet data
        return shodan_data

    # Optional - build out error checking if you'd like
    except Exception as e:
        print(f'Error: {e}')
        raise Exception


# This function runs a search on multiple queries using shodan_facet_search()
def shodan_facet_multiple(shodan_api, search_queries):
    # Facet data to collect
    output_data = {
        'domain':{},
        'port':{},
        'vuln':{}
    }

    # code to run searches, using shodan_facet_search()...
    for query in search_queries:
        # Run search and get results
        results = shodan_facet_search(shodan_api, query)
     
        # code to aggregate data
        for facet in results:
            if facet != 'vuln' and facet != 'domain' and facet != 'port':
                continue
            for value in results[facet]:
                if value['value'] not in output_data[facet]:
                    output_data[facet][value['value']] = 0
                output_data[facet][value['value']] += value['count']

    # Set headers
    headers = ['vuln', 'num_hosts']

    # Sort data alphabetically by vuln
    output_temp = sorted(output_data['vuln'].items())

    # extract data & write output file
    with open(OUTPUT_DIR/'vuln_test_1.csv', 'w', newline='') as csvfile:
        cw = csv.writer(csvfile)

        # write header
        cw.writerow(headers)

        # write rows
        for r in output_temp:
            cw.writerow(r)

    # Set headers
    headers = ['domain', 'num_hosts']
    
    # Sort data alphabetically by vuln
    output_temp = sorted(output_data['domain'].items())

    # extract data & write output file
    with open(OUTPUT_DIR/'vuln_test_2.csv', 'w', newline='') as csvfile:
        cw = csv.writer(csvfile)

        # write header
        cw.writerow(headers)

        # write rows
        for r in output_temp:
            cw.writerow(r)

    # Set headers
    headers = ['ports', 'num_hosts']
    
    # Sort data alphabetically by vuln
    output_temp = sorted(output_data['port'].items())

    # extract data & write output file
    with open(OUTPUT_DIR/'vuln_test_3.csv', 'w', newline='') as csvfile:
        cw = csv.writer(csvfile)

        # write header
        cw.writerow(headers)

        # write rows
        for r in output_temp:
            cw.writerow(r)


if __name__ == "__main__":
    # Initialize API with the Shodan API key
    shodan_api = shodan.Shodan(API_KEY)

    # parse shodan data
    parse_shodan_data()

    # Run search for single query
    query = f'hostname:umd.edu'
    results = shodan_facet_search(shodan_api, query, n_results=5000)

    # Run search for multiple queries
    queries = ['hostname:umd.edu', 'hostname:umces.edu', 'hostname:umm.edu']
    shodan_facet_multiple(shodan_api, queries)