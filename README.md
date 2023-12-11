# Project Name
Shodan is a search engine that focuses on any device connected to the internet compared to regular search engines such as google or bing which focus more on indexing webpages.

In this project, we demonstrate some of what can be accomplished using the Shodan search API.


## How to run
1. Create a python virtual environment(venv) with `python3 -m venv <path-to-venv>` and then `source <path-to-venv/bin/activate` to activate the venv.

2. Then install the Python Shodan library with `pip3 install shodan`

2. Update `API_KEY` with your Shodan API key. Please check the [Shodan docs](https://developer.shodan.io).

3. From the root of the project, run `python3 main.py`.

5. The output files generated will be stored in the `shodan_results` folder. There's already data from previous runs stored in that folder