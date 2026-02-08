#!/usr/bin/env python3
"""
Test script for web search functionality
"""
import asyncio
from tools.web_search import web_search, fetch_url

async def test_search():
    print("Testing web search...")
    result = await web_search("SQL injection CTF writeup", num_results=3)
    print(result)
    print("\n" + "="*50 + "\n")

async def test_fetch():
    print("Testing URL fetch...")
    content = await fetch_url("https://example.com", max_length=500)
    print(content)

if __name__ == "__main__":
    asyncio.run(test_search())
    # asyncio.run(test_fetch())
