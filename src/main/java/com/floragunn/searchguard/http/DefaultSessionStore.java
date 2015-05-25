/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.http;

import java.util.Date;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;

import com.floragunn.searchguard.authentication.User;

public class DefaultSessionStore implements SessionStore {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final ConcurrentHashMap<String, Session> store = new ConcurrentHashMap<String, Session>();

    public DefaultSessionStore() {

        final Timer timer = new Timer();
        timer.schedule(new DestroyAllOldSessionsTask(), 60 * 1000, 60 * 1000);
        //timer.schedule(new DestroyAllSessionsTask(), 3600 * 1000, 10 * 1000);
    }

    @Override
    public Session getSession(final String id) {

        if (id == null) {
            return null;
        }

        return store.get(id);
    }

    @Override
    public Session createSession(final User authenticatedUser) {

        if (authenticatedUser == null) {
            throw new IllegalArgumentException();
        }

        final String id = UUID.randomUUID().toString();
        final Session session = new Session(id, authenticatedUser);
        store.put(id, session);
        return session;
    }

    public void destroyAllSessions() {
        final int count = store.size();
        store.clear();
        log.info("Cleared all {} sessions", count);
    }

    public void destroyOldSessions(final int seconds) {

        int i = 0;
        for (final Iterator<Entry<String, Session>> iterator = store.entrySet().iterator(); iterator.hasNext();) {
            final Entry<String, Session> entry = iterator.next();

            if (entry.getValue().getCreated().before(new Date(System.currentTimeMillis() - (1000 * seconds)))) {
                store.remove(entry.getKey());
                i++;
            }

        }

        log.info("Cleared {} old sessions", i);

    }

    private class DestroyAllSessionsTask extends TimerTask {

        @Override
        public void run() {
            destroyAllSessions();
        }

    }

    private class DestroyAllOldSessionsTask extends TimerTask {

        @Override
        public void run() {
            destroyOldSessions(3600 * 1); //1 h session time
        }

    }

}
