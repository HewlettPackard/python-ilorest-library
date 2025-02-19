python-ilorest-library
======================
.. image:: https://img.shields.io/pypi/v/python-ilorest-library.svg?maxAge=2592000
	:target: https://pypi.python.org/pypi/python-ilorest-library
.. image:: https://img.shields.io/github/release/HewlettPackard/python-ilorest-library.svg?maxAge=2592000
	:target:
.. image:: https://img.shields.io/badge/license-Apache%202-blue.svg
	:target: https://raw.githubusercontent.com/HewlettPackard/python-ilorest-library/master/LICENSE
.. image:: https://img.shields.io/pypi/pyversions/python-ilorest-library.svg?maxAge=2592000
	:target: https://pypi.python.org/pypi/python-ilorest-library

.. contents:: :depth: 1

Description
----------
The python-ilorest-library is a python library built for interacting with the Redfish API remotely to any BMC that 
implements a Redfish API or any HPE system locally. The library also supports HPE's legacy REST API. Go to the library
`documentation <https://hewlettpackard.github.io/python-ilorest-library/API-Overview.html>`_ for more details.

HPE RESTful API for iLO is a RESTful application programming interface for the
management of iLO and iLO Chassis Manager based HPE servers. REST
(Representational State Transfer) is a web based software architectural style
consisting of a set of constraints that focuses on a system's resources. iLO
REST library performs the basic HTTP operations GET, POST, PUT, PATCH and
DELETE on resources using the HATEOAS (Hypermedia as the Engine of Application
State) REST architecture. The API allows the clients to manage and interact
with iLO through a fixed URL and several URIs. Go to the API 
`documentation <https://hewlettpackard.github.io/ilo-rest-api-docs/>`_
for more details.

Installing
----------

.. code-block:: console

	pip install python-ilorest-library

Building from zip file source
~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: console

	python setup.py sdist --formats=zip (this will produce a .zip file)
	cd dist
	pip install python-ilorest-library-x.x.x.zip
	
Including socks support (Version 2.5 or greater)
~~~~~~~~~~~~~~~~~~~~~~~~~
.. code-block:: console

	pip install python-ilorest-library[socks]

.. code-block:: console

	python setup.py sdist --formats=zip (this will produce a .zip file)
	cd dist
	pip install python-ilorest-library-x.x.x.zip[socks]

Requirements
------------

Remote communication
~~~~~~~~~~~~~~~~~~~~
No special requirements.

Inband communication
~~~~~~~~~~~~~~~~~~~~~~~~~

 To enable support for inband communications, you must download the DLL/SO for your system. By downloading, you agree to the terms and conditions of the `Hewlett Packard Enterprise Software License Agreement`_. 
It must be placed in your working environment path.
 
 Windows Chif Driver Download: ilorest_chif.dll_
 
 Linux Chif Driver Download: ilorest_chif.so_
 
 .. _`Hewlett Packard Enterprise Software License Agreement` : https://www.hpe.com/us/en/software/licensing.html
 .. _ilorest_chif.dll: https://github.com/HewlettPackard/python-ilorest-library/releases/tag/v3.6.0.0/ilorest_chif.dll
 .. _ilorest_chif.so: https://github.com/HewlettPackard/python-ilorest-library/releases/tag/v3.6.0.0/ilorest_chif.so

Usage
----------
For usage documentation: https://hewlettpackard.github.io/python-ilorest-library/API-Overview.html

Contributing
----------

 1. Fork it!
 2. Create your feature branch: `git checkout -b my-new-feature`
 3. Commit your changes: `git commit -am 'Add some feature'`
 4. Push to the branch: `git push origin my-new-feature`
 5. Submit a pull request :D

History
-------

  * 04/01/2016: Initial Commit
  * 06/23/2016: Release of v1.1.0
  * 07/25/2016: Release of v1.2.0
  * 08/02/2016: Release of v1.3.0
  * 09/06/2016: Release of v1.4.0
  * 11/04/2016: Release of v1.5.0
  * 12/06/2016: Release of v1.6.0
  * 01/17/2017: Release of v1.7.0
  * 02/01/2017: Release of v1.8.0
  * 03/22/2017: Release of v1.9.0
  * 04/12/2017: Release of v1.9.1
  * 07/17/2017: Release of v2.0.0
  * 10/30/2017: Release of v2.1.0
  * 02/20/2018: Release of v2.2.0
  * 06/11/2018: Release of v2.3.0
  * 07/02/2018: Release of v2.3.1
  * 03/25/2019: Release of v2.4.1
  * 05/09/2019: Release of v2.4.2
  * 07/05/2019: Release of v2.5.0
  * 07/11/2019: Release of v2.5.1
  * 08/13/2019: Release of v2.5.2
  * 11/13/2019: Release of v3.0.0
  * 09/29/2022: Release of v3.6.0
  * 10/14/2024: Release of v5.3.0.0

Copyright and License
---------------------

::

 Copyright 2016 Hewlett Packard Enterprise Development LP

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
