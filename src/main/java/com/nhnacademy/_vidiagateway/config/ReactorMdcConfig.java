package com.nhnacademy._vidiagateway.config;

import jakarta.annotation.PostConstruct;
import org.reactivestreams.Subscription;
import org.slf4j.MDC;
import org.springframework.context.annotation.Configuration;
import reactor.core.CoreSubscriber;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Operators;
import reactor.util.context.Context;

@Configuration
public class ReactorMdcConfig {

    @PostConstruct
    public void setupMdc() {
        Hooks.onEachOperator("mdc", Operators.lift((sc, sub) ->
            new CoreSubscriber<>() {

                @Override
                public Context currentContext() {
                    return sub.currentContext();
                }

                @Override
                public void onSubscribe(Subscription s) {
                    sub.onSubscribe(s);
                }

                @Override
                public void onNext(Object o) {
                    try (MDC.MDCCloseable c =
                             MDC.putCloseable(
                                 "traceId",
                                 currentContext()
                                     .getOrDefault("traceId", "NoID")
                             )) {
                        sub.onNext(o);
                    }
                }

                @Override
                public void onError(Throwable t) {
                    sub.onError(t);
                }

                @Override
                public void onComplete() {
                    sub.onComplete();
                }
            }
        ));
    }
}
