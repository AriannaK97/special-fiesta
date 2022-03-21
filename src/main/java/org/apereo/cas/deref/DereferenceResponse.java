package org.apereo.cas.deref;

import org.ldaptive.SearchResponse;
import org.ldaptive.control.ResponseControl;

import javax.naming.ldap.HasControls;


public class DereferenceResponse extends SearchResponse {

    DereferenceResponse(DereferenceResponseControl dereferenceResponseControl){
        super();
        this.addControls(dereferenceResponseControl);
    }

    @Override
    public boolean isSuccess() {
        return super.isSuccess();
    }

    @Override
    public String getEncodedDiagnosticMessage() {
        return super.getEncodedDiagnosticMessage();
    }

    @Override
    public ResponseControl getControl(String oid) {
        return super.getControl(oid);
    }
}
