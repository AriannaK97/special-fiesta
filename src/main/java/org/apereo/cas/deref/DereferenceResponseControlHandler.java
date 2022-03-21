package org.apereo.cas.deref;

import org.ldaptive.control.ResponseControl;
import org.ldaptive.handler.ResponseControlHandler;

import java.util.function.Consumer;

public class DereferenceResponseControlHandler implements ResponseControlHandler {

    @Override
    public void accept(ResponseControl responseControl) {
        responseControl.getOID();
    }

    @Override
    public Consumer<ResponseControl> andThen(Consumer<? super ResponseControl> after) {
        return ResponseControlHandler.super.andThen(after);
    }
}
