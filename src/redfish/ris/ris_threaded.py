###
# Copyright 2020 Hewlett Packard Enterprise, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
###
# -*- coding: utf-8 -*-
"""A threaded version of RIS _load for quicker searching"""
# ---------Imports---------

import logging
import threading
from queue import Empty

import jsonpath_rw

# Added for py3 compatibility
import six
from six.moves.urllib.parse import urlparse, urlunparse

import redfish.ris

# ---------End of imports---------

# ---------Debug logger---------

LOGGER = logging.getLogger(__name__)

# ---------End of debug logger---------


class LoadWorker(threading.Thread):
    """A threaded implementation of _load for quicker crawling"""

    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
        self.exception = None

    def run(self):
        """Main worker function"""
        try:
            while True:
                (
                    path,
                    includelogs,
                    loadcomplete,
                    crawl,
                    rel,
                    init,
                    prevpath,
                    originaluri,
                    theobj,
                ) = self.queue.get()
                if (
                    path
                    == includelogs
                    == loadcomplete
                    == crawl
                    == rel
                    == init
                    == prevpath
                    == originaluri
                    == theobj
                    == "KILL"
                ):
                    break

                if path.endswith("?page=1") and not loadcomplete:
                    # Don't download schemas in crawl unless we are loading absolutely everything
                    self.queue.task_done()
                    continue
                elif path == "/" or "telemetry" in path.lower() or not path.startswith("/redfish/v1"):
                    self.queue.task_done()
                    continue
                elif not includelogs:
                    # Only include logs when asked as there can be an extreme amount of entries
                    if "/log" in path.lower():
                        self.queue.task_done()
                        continue

                # TODO: need to find a better way to support non ascii characters
                path = path.replace("|", "%7C")
                # remove fragments
                newpath = urlparse(path)
                newpath = list(newpath[:])
                newpath[-1] = ""
                path = urlunparse(tuple(newpath))

                if prevpath and prevpath != path:
                    theobj.ctree[prevpath].update([path])
                if not rel:
                    if path.lower() in theobj.visited_urls:
                        self.queue.task_done()
                        continue
                LOGGER.debug("_loading %s", path)

                resp = theobj._client.get(path)

                if resp.status != 200 and path.lower() == theobj.typepath.defs.biospath:
                    self.queue.task_done()
                    raise redfish.ris.ris.BiosUnregisteredError()
                elif resp.status == 401:
                    self.queue.task_done()
                    raise redfish.ris.ris.SessionExpired(
                        "Invalid session. Please logout and " "log back in or include credentials."
                    )
                elif resp.status not in (201, 200):
                    theobj.removepath(path)
                    self.queue.task_done()
                    continue

                theobj.update_member(resp=resp, path=path, init=init)

                fpath = (
                    lambda pa, path: path
                    if pa.endswith(theobj.typepath.defs.hrefstring) and pa.startswith((theobj.collstr, "Entries"))
                    else None
                )

                # follow all the href attributes
                if theobj.is_redfish:
                    jsonpath_expr = jsonpath_rw.parse("$..'@odata.id'")
                else:
                    jsonpath_expr = jsonpath_rw.parse("$..href")
                matches = jsonpath_expr.find(resp.dict)

                if "links" in resp.dict and "NextPage" in resp.dict["links"]:
                    if originaluri:
                        next_link_uri = originaluri + "?page=" + str(resp.dict["links"]["NextPage"]["page"])
                        href = "%s" % next_link_uri

                        theobj.get_queue.put(
                            (
                                href,
                                includelogs,
                                loadcomplete,
                                crawl,
                                rel,
                                init,
                                None,
                                originaluri,
                                theobj,
                            )
                        )
                    else:
                        next_link_uri = path + "?page=" + str(resp.dict["links"]["NextPage"]["page"])

                        href = "%s" % next_link_uri
                        theobj.get_queue.put(
                            (
                                href,
                                includelogs,
                                loadcomplete,
                                crawl,
                                rel,
                                init,
                                None,
                                path,
                                theobj,
                            )
                        )

                # Only use monolith if we are set to
                matchrdirpath = (
                    next(
                        (match for match in matches if match.value == theobj._resourcedir),
                        None,
                    )
                    if theobj.directory_load
                    else None
                )
                if not matchrdirpath and crawl:
                    for match in matches:
                        if path == "/rest/v1" and not loadcomplete:
                            if (
                                str(match.full_path) == "links.Schemas.href"
                                or str(match.full_path) == "links.Registries.href"
                            ):
                                continue
                        elif not loadcomplete:
                            if (
                                str(match.full_path) == "Registries.@odata.id"
                                or str(match.full_path) == "JsonSchemas.@odata.id"
                            ):
                                continue

                        if match.value == path:
                            continue
                        elif not isinstance(match.value, six.string_types):
                            continue

                        href = "%s" % match.value
                        theobj.get_queue.put(
                            (
                                href,
                                includelogs,
                                loadcomplete,
                                crawl,
                                rel,
                                init,
                                fpath(str(match.full_path), path),
                                originaluri,
                                theobj,
                            )
                        )
                elif crawl:
                    href = "%s" % matchrdirpath.value
                    theobj.get_queue.put(
                        (
                            href,
                            includelogs,
                            loadcomplete,
                            crawl,
                            rel,
                            init,
                            path,
                            originaluri,
                            theobj,
                        )
                    )
                if loadcomplete:
                    if path == "/rest/v1":
                        schemamatch = jsonpath_rw.parse("$..extref")
                    else:
                        schemamatch = jsonpath_rw.parse("$..Uri")
                    smatches = schemamatch.find(resp.dict)
                    matches = matches + smatches
                    for match in matches:
                        if isinstance(match.value, six.string_types):
                            theobj.get_queue.put(
                                (
                                    match.value,
                                    includelogs,
                                    loadcomplete,
                                    crawl,
                                    rel,
                                    init,
                                    fpath(str(match.full_path), path),
                                    originaluri,
                                    theobj,
                                )
                            )
                self.queue.task_done()
        except Empty:
            pass
        except Exception as excp:
            self.exception = excp

    def get_exception(self):
        """Get any exception from the thread"""
        return self.exception