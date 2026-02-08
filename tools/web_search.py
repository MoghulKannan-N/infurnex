import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
from cai.sdk.agents import function_tool

@function_tool
async def web_search(query: str, num_results: int = 5) -> str:
    """
    Search the web using DuckDuckGo and return results.
    
    Args:
        query: Search query string
        num_results: Number of results to return (default 5)
    
    Returns:
        Formatted search results with titles, snippets, and URLs
    """
    try:
        # DuckDuckGo HTML search (no API key needed)
        encoded_query = quote_plus(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded_query}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        results = []
        for result in soup.find_all('div', class_='result', limit=num_results):
            try:
                title_tag = result.find('a', class_='result__a')
                snippet_tag = result.find('a', class_='result__snippet')
                
                if title_tag and snippet_tag:
                    title = title_tag.get_text(strip=True)
                    url = title_tag.get('href', '')
                    snippet = snippet_tag.get_text(strip=True)
                    
                    results.append(f"Title: {title}\nURL: {url}\nSnippet: {snippet}\n")
            except:
                continue
        
        if not results:
            return "No results found."
        
        return "\n---\n".join(results)
    
    except Exception as e:
        return f"Search failed: {str(e)}"


@function_tool
async def fetch_url(url: str, max_length: int = 5000) -> str:
    """
    Fetch content from a URL and return the text.
    
    Args:
        url: URL to fetch
        max_length: Maximum characters to return (default 5000)
    
    Returns:
        Text content from the URL
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        }
        
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # Parse HTML and extract text
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer"]):
            script.decompose()
        
        # Get text
        text = soup.get_text(separator='\n', strip=True)
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length] + "...\n[Content truncated]"
        
        return text
    
    except Exception as e:
        return f"Failed to fetch URL: {str(e)}"
