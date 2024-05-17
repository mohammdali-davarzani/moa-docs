---
sidebar_position: 3
description: steps of fuzzing target
---

# increasing attack surfaces 
## side applications 
	- mobile applications 
	- computer applications 
## many hidden surfaces out there
		- https://github.com/Voorivex/narrow-app
		- hidden parameters, paths, files, etc
		- paid, forgotten or custom features 
		- stage instances, even out of scopes
## passive crawling (every where) 
#### concept 
			- without sending an http request to the target 
			- relies on existing sources of data 
#### search engine dorking 
			- search engine -> URL -> vuln 
			- search engine -> URL -> data > help to find vuln 
			- to find sensitive information indexed 
			- to discover interesting paths
			- Google and Bing, not or!
			- keywords + operators 
				- site:, extention:, -something ( exclude something) 
			- repeat the search with the omitted results included 
			- make your own dork string based on the target

            ##### dorker application
            ```html
            <!DOCTYPE html>
            <html>

            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Google Dorker</title>
            <style>
                /* Reset default browser styles */
                * {
                font-family: Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
                background-color: #f0f0f0;
                color: #333;
                }

                hr {
                display: block;
                margin: auto;
                }
            </style>
            </head>

            <body>
            <h1>Google Dorker</h1>
            <input class="domain" id="domain" oninput="updateSearchQuery()" size="50" value="voorivex.academy"></input><br><br>
            <div class="results" id="results"></div>
            <script>
                function updateSearchQuery() {
                var domain = document.getElementById('domain').value.trim();
                var dorks = [
                    'site:' + domain + ' inurl:&',
                    'site:' + domain + ' ext:php | ext:aspx | ext:asp | ext:jsp | ext:html | ext:htm',
                    'site:' + domain + ' ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:xml',
                    'site:' + domain + ' inurl:url= | inurl:return= | inurl:next= | inurl:redir= inurl:http',
                    'site:' + domain + ' inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain= | inurl:page= inurl:&',
                    'site:' + domain + ' inurl:config | inurl:env | inurl:setting | inurl:backup | inurl:admin | inurl:php',
                    'site:' + domain + ' inurl:email= | inurl:phone= | inurl:password= | inurl:secret= inurl:&',
                    'site:' + domain + ' inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer',
                    'site:' + domain + ' inurl:cmd | inurl:exec= | inurl:query= | inurl:code= | inurl:do= | inurl:run= | inurl:read= | inurl:ping= inurl:&',
                    'site:' + domain + ' inurl:(unsubscribe|register|feedback|signup|join|contact|profile|user|comment|api|developer|affiliate|upload|mobile|upgrade|password)',
                    'site:' + domain + ' intitle:"Welcome to Nginx"',
                ];

                var resultsDiv = document.getElementById('results');
                resultsDiv.innerHTML = '';

                dorks.forEach(function (dork) {
                    var link = 'https://www.google.com/search?q=' + encodeURIComponent(dork);

                    var linkElement = document.createElement('a');
                    linkElement.href = link;
                    linkElement.target = '_blank';
                    linkElement.textContent = dork;
                    resultsDiv.appendChild(linkElement);

                    resultsDiv.appendChild(document.createElement('br'));
                });
                }

                updateSearchQuery()
            </script>
            </body>

            </html>
        ```

#### wayback machine 
			- a non-profit organization based in San Francisco, California
			- https://archive.org 
			- may lead to hidden resources 
			- usage 
				- server API - https://archive.org/developers/wayback-cdx-server.html
					goals : 
						1. old data 
						2. URLs + parameters
				- examples 
					- https://web.archive.org/cdx/search/cdx?url=https://icollab.info
					- https://web.archive.org/web/20211208105512if_/http://icollab.info
					- https://web.archive.org/cdx/search/cdx?
					- url=*.capcut.com/*&fl=timestamp,original&collapse=digest
					- https://web.archive.org/cdx/search/cdx?url=*.capcut.com/*&fl=original&collapse=urlkey
#### tools 
			* mass hunt (automation) 
			* manual hunt -> single target -> NO DUP FILTERING  
			- waybackurls
			 	- still the best 
			 	- output cleaning is needed 
			 	- use with main domain 
			- gau 
				-  sources 
					- archive.org
					- commoncrawl.org
					- urlscan.io
					- alienvault.com
				- output cleaning is needed
				- use with main domain 

#### nice_passive script 
```python 
#!/usr/bin/env python3
import sys, os, tempfile, subprocess
from urllib.parse import urlparse, urlsplit

def run_command_in_zsh(command):
    try:
        result = subprocess.run(["zsh", "-c", command], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("Error occurred:", result.stderr)
            return False

        return result.stdout.strip()
    except subprocess.CalledProcessError as exc:
        print("Status : FAIL", exc.returncode, exc.output)

class colors:
    GRAY = "\033[90m"

def get_hostname(url):
    if url.startswith('http'):
        # Split the URL into components
        url_components = urlsplit(url)
        # Get the hostname from the netloc component
        return url_components.netloc
    else:
        return url

def good_url(url):
    extensions = ['.json', '.js', '.fnt', '.ogg', '.css', '.jpg', '.jpeg', '.png', '.svg', '.img', '.gif', '.exe', '.mp4', '.flv', '.pdf', '.doc', '.ogv', '.webm', '.wmv', '.webp', '.mov', '.mp3', '.m4a', '.m4p', '.ppt', '.pptx', '.scss', '.tif', '.tiff', '.ttf', '.otf', '.woff', '.woff2', '.bmp', '.ico', '.eot', '.htc', '.swf', '.rtf', '.image', '.rf', '.txt', 'xml', 'zip']
    try:
        parsed_url = urlparse(url)
        for ext in extensions:
            if (parsed_url.path).endswith(ext):
                return False

        return True
    except Exception as e:
        print(f"Error: {str(e)}")
        return None
    
def finalize(file_path, domain):
    unique_lines = set()
    with open(file_path, 'r') as file:
        for line in file:
            if good_url(line):
                unique_lines.add(line.strip())
    
    unique_lines = {value for value in unique_lines if value}

    if len(unique_lines) == 0:
        return False
    
    with open(f"{domain}.passive", 'w') as file:
        for element in unique_lines:
            file.write(str(element) + '\n')

    return unique_lines

def is_file(filepath):
    # Check if the path exists and is a file
    return os.path.isfile(filepath)

def generate_temp_file():
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
        return temp_file.name

def run_nice_passive(domain):

    temp_file = generate_temp_file()
    print(f"{colors.GRAY}gathering URLs passively for: {domain}{colors.GRAY}")

    commands = [
        f"echo https://{domain}/ | tee {temp_file}",
        f"echo {domain} | waybackurls | sort -u | tee -a {temp_file}",
        f"gau {domain} --threads 1 --subs | sort -u | tee -a {temp_file}"
    ]

    # running commands
    for command in commands:
        print(f"{colors.GRAY}Executing commands: {command}{colors.GRAY}")
        res = run_command_in_zsh(command)

    print(f"{colors.GRAY}merging resulst for: {domain}{colors.GRAY}")
    res = finalize(temp_file, domain)

    res_num = len(res) if res else 0
    print(f"{colors.GRAY}done for {domain}, results: {res_num}{colors.GRAY}")

def get_input():
    # Check if input is provided through stdin
    if not sys.stdin.isatty():
        return sys.stdin.readline().strip()
    # Check if input is provided through command-line arguments
    elif len(sys.argv) > 1:
        return sys.argv[1]
    else:
        return None

if __name__ == "__main__":
    input = get_input()

    if input is None:
        print(f"Usage: echo domain.tld | nice_passive")
        print(f"Usage: cat domains.txt | nice_passive")
        sys.exit()

    if is_file(input):
        with open(input, 'r') as file:
            for line in file:
                domain = get_hostname(line)
                run_nice_passive(domain)
    else:
        run_nice_passive(get_hostname(input))
```
			
## active crawling 
#### katana 
			- not suitable for DOM based applications 
			- custom configuration according to the target 
###### nice_katana script
```bash 
nice_katana () {
    while read line
    do
        host=$(echo $line | unfurl format %d)
        echo "$line" | katana -js-crawl -jsluice -known-files all -automatic-form-fill -silent -crawl-scope $host -extension-filter json,js,fnt,ogg,css,jpg,jpeg,png,svg,img,gif,exe,mp4,flv,pdf,doc,ogv,webm,wmv,webp,mov,mp3,m4a,m4p,ppt,pptx,scss,tif,tiff,ttf,otf,woff,woff2,bmp,ico,eot,htc,swf,rtf,image,rf,txt,ml,ip | tee ${host}.katana
    done < "${1:-/dev/stdin}"
}
```
#### JavaScript 
			- manual review is the best method 
			- some scripts maybe helpful 
##### fetch urls (in browser console)
```js 
javascript:(function(){var scripts=document.getElementsByTagName("script"),regex=/(?<=(\"|\'|\`))\/[a-zA-Z0-9_?&=\/\-\#\.]*(?=(\"|\'|\`))/g;const results=new Set;for(var i=0;i<scripts.length;i++){var t=scripts[i].src;""!=t&&fetch(t).then(function(t){return t.text()}).then(function(t){var e=t.matchAll(regex);for(let r of e)results.add(r[0])}).catch(function(t){console.log("An error occurred: ",t)})}var pageContent=document.documentElement.outerHTML,matches=pageContent.matchAll(regex);for(const match of matches)results.add(match[0]);function writeResults(){results.forEach(function(t){document.write(t+"<br>")})}setTimeout(writeResults,3e3);})();
```
	