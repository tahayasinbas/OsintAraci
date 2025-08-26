import scrapy
from ..items import VericrawlerItem
import json


class SearchcrawlerSpider(scrapy.Spider):
    name = "SearchCrawler"
    allowed_domains = ["www.kvkk.gov.tr"]
    
    def __init__(self, arama_kelimesi='', *args, **kwargs):
        super(SearchcrawlerSpider, self).__init__(*args, **kwargs)
        self.arama_kelimesi = arama_kelimesi
    
    def start_requests(self):
        # Terminal yerine parametre olarak arama kelimesini al
        if not self.arama_kelimesi:
            self.arama_kelimesi = getattr(self, 'arama_kelimesi', '')
        
        url = f"https://www.kvkk.gov.tr/Search?keyword={self.arama_kelimesi}&langText=tr"
        yield scrapy.Request(url=url, callback=self.arama_parse)

    def arama_parse(self, response):
        # Sayfadaki linkleri takip et
        sayfa_linkleri = response.xpath("//a[@class='arrow-link']/@href").getall()
        for sayfa_link in sayfa_linkleri:
            yield response.follow(sayfa_link, self.sayfa_parse)

        # Sonraki sayfaya git
        sonraki_sayfa = response.xpath("//a[text()='Sonraki']/@href").get()
        if sonraki_sayfa:
            yield response.follow(sonraki_sayfa, self.arama_parse)

    def sayfa_parse(self, response):
        arama_sonucu_baslik = response.xpath("//h3[@class='widget-title']/text()").get()
        arama_sonucu_yazi = response.xpath("//div[@class='blog-post-inner']//text()").getall()
        
        item = VericrawlerItem()
        item["AramaSonucuBaslik"] = arama_sonucu_baslik
        item["AramaSonucYazi"] = arama_sonucu_yazi[1:] if arama_sonucu_yazi else []
        yield item
