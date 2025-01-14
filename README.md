<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->

[![Contributors](https://img.shields.io/github/contributors/jmkemp20/lua-devp2p-wireshark-dissector?style=for-the-badge)](https://github.com/jmkemp20/lua-devp2p-wireshark-dissector/graphs/contributors)
[![Forks](https://img.shields.io/github/forks/jmkemp20/lua-devp2p-wireshark-dissector?style=for-the-badge)](https://github.com/jmkemp20/lua-devp2p-wireshark-dissector/network)
[![Stargazers](https://img.shields.io/github/stars/jmkemp20/lua-devp2p-wireshark-dissector?style=for-the-badge)](https://github.com/jmkemp20/lua-devp2p-wireshark-dissector/stargazers)
[![Issues](https://img.shields.io/github/issues/jmkemp20/lua-devp2p-wireshark-dissector?style=for-the-badge)](https://github.com/jmkemp20/lua-devp2p-wireshark-dissector/issues)
[![License](https://img.shields.io/github/license/jmkemp20/lua-devp2p-wireshark-dissector?style=for-the-badge)](https://github.com/jmkemp20/lua-devp2p-wireshark-dissector/blob/main/LICENSE.txt)
[![LinkedIn][linkedin-shield]][linkedin-url]

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/jmkemp20/lua-devp2p-wireshark-dissector">
    <img src="images/luadevp2p.png" alt="Logo" width="200" height="80">
  </a>

  <h3 align="center">LUA devp2p Wireshark Dissector</h3>

  <p align="center">
    LUA Wireshark Dissector Plugin to add Ethereum's devp2p Protocol Suite
    <br />
    <a href="https://github.com/jmkemp20/lua-devp2p-wireshark-dissector"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/ethereum/devp2p">devp2p</a>
    ·
    <a href="https://github.com/jmkemp20/lua-devp2p-wireshark-dissector/issues">Report Bug</a>
    ·
    <a href="https://github.com/jmkemp20/lua-devp2p-wireshark-dissector/issues">Request Feature</a>
  </p>
</p>

<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#python-toolkit">Python Toolkit</a></li>
        <li><a href="#lunatic-python">Lunatic Python</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#reference">Reference</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

This is originally forked from the [bcsecorg](https://github.com/bcsecorg/ethereum_devp2p_wireshark_dissector) version of the LUA devp2p wireshark dissector plugin. With heavy modifications, cleanup and feature additions, there exists very little resemblence. The goal is to provide an all-encompassing wireshark dissector plugin that can dissect/decipher/decrypt devp2p network traffic. This includes UDP peer discovery and authenticated peer discovery (discv4 and discv5), RLPx application level protocols and their payloads (ETH, SNAP), along with a full fledged decryption suite and RLP decoding toolset for Wireshark.

Currently, no other Wireshark Dissector provides dissecting encrypted traffic within a devp2p network, so this project's goal is to provide one, for developers, analysts and the community. In support of deciphering and decrypting devp2p network traffic, a python-based library [pydevp2p](https://github.com/jmkemp20/pydevp2p) was created to aid in node/peer management, decrypting, and RLP decoding.

Because of the use of a python-based library, this tool also utilizes a LUA <-> Python 3.10 bridge known as Lunatic Python, [lunatic-python](https://github.com/jmkemp20/lunatic-python). This also needed to be forked, in order to work with LUA 4.2 and Python 3.10.

There also exists a C-based ethereum dissector that requires compiling and building Wireshark, [ConsenSys](https://github.com/ConsenSys/ethereum-dissectors), but with only discv4 dissection.

<!--[![Product Name Screen Shot][product-screenshot]](https://example.com)-->

### Python Toolkit

- [pydevp2p](https://github.com/jmkemp20/pydevp2p) - A Toolkit Helper Library for Ethereum ECIES and Devp2p

### Lunatic Python

- [lunatic-python](https://github.com/jmkemp20/lunatic-python) - A two-way bridge between Python and Lua

<!-- GETTING STARTED -->

## Getting Started

To get a local copy up and running follow these simple steps.

### Prerequisites

- NOTE - Wireshark uses a specifically built LUA runtime based off of LUA 5.2, therefore lunatic-python needs to be built towards that version

- LUA Dependencies
  ```sh
  sudo apt-get install lua5.2 liblua5.2-dev
  ```
- Build [lunatic-python](https://github.com/jmkemp20/lunatic-python) for LUA 5.2 - Click the link for more detailed build instructions
  ```sh
  cd lunatic-python
  cmake -B./build -H. -DPYTHON_INCLUDE_DIR=/usr/include/python3.10 \
    -DPYTHON_LIBRARY=/usr/lib/x86_64-linux-gnu/libpython3.10.so
  cmake --build ./build
  ```
- Make sure [pydevp2p](https://github.com/jmkemp20/pydevp2p) is installed (use sudo if you will be running Wireshark with Root privileges)
  ```sh
  cd pydevp2p
  pip install .
  ```

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/jmkemp20/lua-devp2p-wireshark-dissector.git
   cd lua-devp2p-wireshark-dissector
   ```
2. Copy over the python.so shared object library to global and/or local LUA includes folder
   ```sh
   cp ~/lunatic-python/build/bin/python.so /usr/local/lib/lua/5.2/.
   ```
3. Run the testing.lua script to verify LUA <-> PYTHON bridge
   ```sh
   lua testing.lua
   ```
4. Create Wireshark Plugins folders that resemble below (if they don't exist)
   ```sh
   ~/.local/lib/wireshark/plugins/...     # For local user
   /root/.local/lib/wireshark/plugins/... # For root user
   ```
5. Symlink the .lua dissectors from this repo to the Wireshark plugins folder
   ```sh
   cd ~/.local/lib/wireshark/plugins      # For local user
   sudo ln -s {path-to-dissectors}/{dissector-name}.lua {dissector-name}.lua
   cd /root/.local/lib/wireshark/plugins  # For root user
   sudo ln -s {path-to-dissectors}/{dissector-name}.lua {dissector-name}.lua
   ```

<!-- USAGE EXAMPLES -->

## Usage

1. Run Wireshark
   ```sh
   wireshark
     OR
   wireshark -r <pcapng-file>
   ```

<!-- ROADMAP -->

## Roadmap

See the [open issues](https://github.com/jmkemp20/lua-devp2p-wireshark-dissector/issues) for a list of proposed features (and known issues).

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the MIT License. See `LICENSE` for more information.

<!-- CONTACT -->

## Contact

Joshua Kemp - kemp3jm@dukes.jmu.edu

Project Link: [https://github.com/jmkemp20/lua-devp2p-wireshark-dissector](https://github.com/jmkemp20/lua-devp2p-wireshark-dissector)

<!-- ACKNOWLEDGEMENTS

## Acknowledgements

- []()
- []()
- []()

<!-- MARKDOWN LINKS & IMAGES
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/joshua-kemp20/

## REFERENCE

- devp2p overview https://github.com/ethereum/devp2p
- Node Discovery Protocol v4 https://github.com/ethereum/devp2p/blob/master/discv4.md
- RLP (Recursive Length Prefix) https://github.com/ethereum/wiki/wiki/RLP
