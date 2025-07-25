/*
 * Copyright 2017 Scott Weeden and/or his affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.timer.basic;

import java.util.TimerTask;

import org.keycloak.timer.TimerProvider;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TimerTaskContextImpl implements TimerProvider.TimerTaskContext {

    private final Runnable runnable;
    final TimerTask timerTask;
    private final long intervalMillis;

    public TimerTaskContextImpl(Runnable runnable, TimerTask timerTask, long intervalMillis) {
        this.runnable = runnable;
        this.timerTask = timerTask;
        this.intervalMillis = intervalMillis;
    }

    @Override
    public Runnable getRunnable() {
        return runnable;
    }

    @Override
    public long getIntervalMillis() {
        return intervalMillis;
    }
}
