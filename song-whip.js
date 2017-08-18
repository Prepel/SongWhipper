
var curl = require('curl');
var DomParser = require('dom-parser');
var parser = new DomParser();

// TODO ecmascript 6 classes?
var songwhip = function Songwhip(url, callback) {
    this.url = url;
    this.callback = callback
    this.songName;
    this.artistName;
    this.links;
}

songwhip.prototype.getSongName = function()
{
    return this.songName;
}

songwhip.prototype.getArtistName = function()
{
    return this.artistName;
}

songwhip.prototype.getLinks = function()
{
    return this.links;
}

songwhip.prototype.run = function() {
    this.validateUrl()
};

songwhip.prototype.validateUrl = function ()
{
    curl.post('https://songwhip.com', this.url, this.validateUrlCallback.bind(this));
};

songwhip.prototype.validateUrlCallback = function(err, response, body)
{

    if(!body.includes('Error'))
    {
        var urlData = JSON.parse(body)
        this.getUrls(urlData); // call it on songwhip since we are in a callback
    }
};

songwhip.prototype.getUrls = function(data)
{
    if(data.url){
        curl.get( data.url, this.getUrlsCallback.bind(this));  
    }
};

songwhip.prototype.getUrlsCallback = function (err, response, body)
{
    var dom = parser.parseFromString(body);
    // todo type="application/ld+json"
    var jsonString = dom.getElementsByTagName('script')[2].innerHTML.replace("window.DATA = ", "")
    jsonString = jsonString.substring(0, jsonString.length - 1);
    var data = JSON.parse(jsonString);
    console.log( data );

    this.loadDataFromUrlsCallback(data);
};

songwhip.prototype.loadDataFromUrlsCallback = function(data)
{
    if(data.name) {
        this.songName = data.name;
        if(typeof data.artists !== 'undefined' && typeof data.artists[0] !== 'undefined') {
            this.artistName = data.artist.name;
        } else {
            this.artistName = '';
        }
        this.links = data.links;

        this.callback(this);
        // callback to server or call a function in server.
    }

};

// todo add country validation.
songwhip.prototype.getLinkUrl = function (key)
{
    var url = this.links[key].link;
    return url;
};


module.exports = songwhip;