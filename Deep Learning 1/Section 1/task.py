import requests
import spacy
import sublist3r
import os
os.environ['LOKY_MAX_CPU_COUNT'] = '4'  # Replace 4 with the number of cores you want to use
from sklearn.feature_extraction.text import TfidfVectorizer
from bs4 import BeautifulSoup
from sklearn.cluster import KMeans
from bs4 import BeautifulSoup
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import requests
from bs4 import BeautifulSoup
import os
import warnings
print('HTML CODE')
def fetch_data(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup

# Example usage
url = 'https://selfmade.ninja/'
data = fetch_data(url)
print(data.prettify())

print('SUBDOMAINS')

def get_subdomains(domain):
    # Use Sublist3r to enumerate subdomains
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
    return subdomains
domain = input("Enter the domain name (e.g., example.com): ")
print(f"Finding subdomains for {domain}...\n")
subdomains = get_subdomains(domain)
if subdomains:
    print(f"Found {len(subdomains)} subdomains:\n")
    for subdomain in subdomains:
        print(subdomain)
else:
    print("No subdomains found.")


print('LIST OF DOMAIN ')
def scrape_website(url):
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        return None

def extract_links_from_html(html):
    soup = BeautifulSoup(html, 'html.parser')
    links = []
    for link in soup.find_all('a'):
        href = link.get('href')
        if href:
            links.append(href)
    return links
nlp = spacy.load("en_core_web_sm")

def extract_cyber_related_info(text):
    doc = nlp(text)
    cyber_keywords = ["cyber incident", "data breach", "hacking", "malware", "ransomware"]
    entities = []
    
    for token in doc:
        if token.text.lower() in cyber_keywords:
            entities.append(token.text)
    
    return entities

def classify_platforms(texts):
    # Initialize the TfidfVectorizer
    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(texts)
    
    # Set the number of clusters to be less than or equal to the number of samples
    n_clusters = min(len(texts), 3)  # Adjust this as needed
    kmeans = KMeans(n_clusters=n_clusters, random_state=0)
    kmeans.fit(X)
    
    return kmeans.labels_

# Example usage
url = "https://selfmade.ninja"  # Replace with the target URL
html_content = scrape_website(url)
if html_content:
    links = extract_links_from_html(html_content)
    print(links)
sample_text = "A new cyber incident was reported involving ransomware."
extracted_info = extract_cyber_related_info(sample_text)
print(extracted_info)
sample_texts = [
    "This platform reports cyber incidents.",
    "This is a general news site.",
    "New ransomware attack reported."
]

platform_labels = classify_platforms(sample_texts)
print(platform_labels)
urls = ["https://selfmade.ninja/", "https://www.gmail.com"]
all_texts = []

for url in urls:
    html_content = scrape_website(url)
    if html_content:
        links = extract_links_from_html(html_content)
        # You can further scrape these links if needed
        all_texts.append(html_content)

# Process the text data to identify cyber-related information
relevant_texts = []
for text in all_texts:
    info = extract_cyber_related_info(text)
    if info:
        relevant_texts.append(text)

# Use ML to classify the relevance of each platform
platform_labels = classify_platforms(relevant_texts)
print(platform_labels)

# Suppress the specific warning
warnings.filterwarnings("ignore", category=UserWarning, module='joblib.externals.loky')

# Set LOKY_MAX_CPU_COUNT to the number of cores you want to use
os.environ['LOKY_MAX_CPU_COUNT'] = '4'  # Adjust the number based on your needs

# Step 1: Collect data from known cyber security websites for training
known_urls = [
    "https://krebsonsecurity.com/",
    "https://threatpost.com/",
    "https://www.darkreading.com/",
    "https://thehackernews.com/",
    "https://arstechnica.com/security/",
    "https://techcrunch.com/tag/security/",
    "https://www.cyberscoop.com/",
    "https://isc.sans.edu/",
    "https://www.scmagazine.com/",
    "https://www.grahamcluley.com/"
]

# Step 2: Crawl these URLs and collect text content
def fetch_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Check for HTTP errors
        soup = BeautifulSoup(response.content, 'html.parser')
        return ' '.join([p.text for p in soup.find_all('p')])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching content from {url}: {e}")
        return ""

# Collect content from all known URLs
contents = [fetch_content(url) for url in known_urls]

# Step 3: Vectorize the content
vectorizer = TfidfVectorizer(stop_words='english')
X = vectorizer.fit_transform(contents)
print(X.toarray())

# Step 4: Apply KMeans to find clusters of relevant platforms
kmeans = KMeans(n_clusters=5, random_state=42).fit(X)
print("Cluster centers:\n", kmeans.cluster_centers_)
print("Labels:\n", kmeans.labels_)

# Use the trained model to predict new URLs/platforms
def predict_platform(url):
    content = fetch_content(url)
    if content:  # Only predict if content was successfully fetched
        vectorized = vectorizer.transform([content])
        return kmeans.predict(vectorized)
    else:
        return [None]  # Return a placeholder if content fetching failed

# Inspect contents from known URLs
for url, content in zip(known_urls, contents):
    print(f"URL: {url}")
    print(f"Content (first 500 chars): {content[:500]}\n")

# Inspect KMeans cluster centers
print("Cluster centers:\n", kmeans.cluster_centers_)

# Inspect predictions for a few new URLs
test_urls = ["https://google.com", "https://selfmade.ninja"]
for url in test_urls:
    cluster = predict_platform(url)
    if cluster[0] is not None:
        print(f"URL: {url} classified as cluster: {cluster[0]}")
    else:
        print(f"URL: {url} could not be classified")

# Example usage:
new_url = "https://google.com"
is_relevant = predict_platform(new_url)
if is_relevant[0] is not None:
    print(f"The new URL is classified as cluster: {is_relevant[0]}")
else:
    print(f"The new URL could not be classified")
