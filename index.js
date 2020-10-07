'use strict';

require('dotenv').config();

const axios = require('axios');
const client = require('shodan-client');
const fs = require('fs').promises;
const EOL = require('os').EOL;

const lookUp = async (search) => {
    const res = await axios.get(`https://api.shodan.io/labs/honeyscore/${search}?key=${process.env.SHODAN_API}`);

    return res.data;
}

(async () => {

    const searchData = await fs.readFile('./search_list', 'utf8');
    const searchList = searchData.split(EOL);

    for(let itemSearch of searchList) {

        const res = await client.host(itemSearch, process.env.SHODAN_API, {minify: true});

        const data = {
            host: itemSearch,
            ports: res.ports || [],
            exploits: res.vulns || [],
            isp: res.isp,
            honeypot: await lookUp(itemSearch)
        };

        console.log(data);
    }
})();

