..
      Copyright (c) 2019 AT&T Intellectual Property. All Rights Reserved.

      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
      You may obtain a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

.. _api:

Radio Edge Cloud Remote Installer - Version 1
=============================================
The Akraino REC Remote Installer API is a RESTful interface used to trigger a
deployment of a Radio Edge Cloud cluster from an Akraino Regional Controller.

For version 1 of the API, all endpoints are located under ``/v1/``.

The API runs on a CRUD model; Create (POST), Read (GET), Update (PUT), Delete (DELETE)
operations may be performed although PUT and DELETE are not currently used.
Not all operations may be allowed for all objects.

All content provided to the API must be in JSON form (with a Content-Type of
``application/json``).
All output provided by the API will be in JSON form (with a Content-Type of
``application/json``).

At this time there is only the installation API.

.. _installation-api:

Installation API
----------------
The Installation API allows a user to request or monitor an installation.

POST /v1/installations/
^^^^^^^^^^^^^^^^^^^^^^^

Provide a user config file which will be passed on to the REC deployer component
and an ISO disk image containing the REC deployer. The user config file is often
named user_config.yaml and an `example template`_ is available.

.. _example template: https://gerrit.akraino.org/r/gitweb?p=ta/config-manager.git;a=blob;f=userconfigtemplate/user_config.yaml;h=1e1e257efd99c433205d63d8fb75a821520a6d87;hb=refs/heads/master

Sample JSON input content:

.. code-block:: json

  {
    "user-config": "<user config yaml filename>",
    "iso": "<iso-image-name>"
    "provisioning-iso": "<provisioning-iso-name>"
  }

Sample JSON response:

.. code-block:: json
  {
    "uuid": "<operation identifier>"
  }


===========  ======================================================================
Return Code  Reason
===========  ======================================================================
200          Successful initiation of installation.
400          Invalid content supplied.
500          Internal error.
===========  ======================================================================

GET /v1/installations/<uuid>/state
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Retrieve the status of an installation (progress or completion).

Response body in JSON:

.. code-block:: json

  {
   "status": <ongoing|completed|failed>,
   "description": <description about the progress>,
   "percentage": <percentage completed of the installation>
  }


===========  ======================================================================
Return Code  Reason
===========  ======================================================================
200          Successful execution.
===========  ======================================================================

POST /v1/installations/<uuid>
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Used by the REC deployer to report progress of an installation that was
initiated by the Remote Installer

Request body in JSON:

.. code-block:: json

  {
   "status": <ongoing|completed|failed>,
   "description": <description about the progress>,
   "percentage": <percentage completed of the installation>
  }

===========  ======================================================================
Return Code  Reason
===========  ======================================================================
200          Successful execution.
===========  ======================================================================

