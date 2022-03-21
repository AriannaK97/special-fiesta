package org.apereo.cas.deref;

import lombok.extern.slf4j.Slf4j;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapUtils;
import org.ldaptive.SearchResponse;
import org.ldaptive.handler.AbstractEntryHandler;
import org.ldaptive.handler.SearchResultHandler;

import javax.naming.ldap.HasControls;
import java.util.ArrayList;
import java.util.HashMap;

import static org.ldaptive.SearchResponse.builder;


/**
 * Callback interface used by LdapTemplate search, list and listBindings
 * methods, also adding support for the dereference control. Implementations
 * of this interface perform the actual work of extracting results from a
 * single NameClassPair returned by an LDAP search operation.
 */

@Slf4j
public class DereferenceResultHandler extends AbstractEntryHandler<SearchResponse> implements SearchResultHandler {

    private HashMap<String, ArrayList<Object>> attrs;
    private HashMap<String,ArrayList<Object>> derefAttrs;

    public HashMap<String,ArrayList<Object>> getAttrs() {
        return attrs;
    }

    public HashMap<String,ArrayList<Object>> getDerefAttrs() {
        return derefAttrs;
    }

    private static final int HASH_CODE_SEED = 857;



    private SearchResponse dereference(SearchResponse result){
        LdapEntry mergedEntry = null;
        if (result != null) {
            for (LdapEntry entry : result.getEntries()) {
                if (mergedEntry == null) {
                    mergedEntry = entry;
                } else {
                    for (LdapAttribute la : entry.getAttributes()) {
                        final LdapAttribute oldAttr = mergedEntry.getAttribute(la.getName());
                        if (oldAttr == null) {
                            mergedEntry.addAttributes(la);
                        } else {
                            if (oldAttr.isBinary()) {
                                oldAttr.addBinaryValues(la.getBinaryValues());
                            } else {
                                oldAttr.addStringValues(la.getStringValues());
                            }
                        }
                    }
                }
            }
        }
        return mergedEntry != null ?
                builder()
                        .entry(
                                LdapEntry.builder().dn(mergedEntry.getDn()).attributes(mergedEntry.getAttributes()).build())
                        .build() :
                new SearchResponse();
    }

    private SearchResponse dereferenceResponse (SearchResponse searchResponse){
        derefAttrs = new HashMap<String,ArrayList<Object>>();
        if( searchResponse instanceof DereferenceResponse) {
            DereferenceResponseControl respCtrl = null;
            try {
                respCtrl = new DereferenceResponseControl(searchResponse);
            }
            catch( Exception e) {
                LOGGER.error("Error creating dereference response control!"
                        + "Will try to return normal attributes at least.",e);

                return dereference(searchResponse);
            }

            derefAttrs = (HashMap<String,ArrayList<Object>>) respCtrl.getDereferenceAttrs();
            attrs=(HashMap<String,ArrayList<Object>>)respCtrl.getAttrs();
        } else {
            LOGGER.warn("No dereference control was found in the response."
                    + "Will try to return the normal -not dereferenced- user attributes");
            return dereference(searchResponse);
        }
        return dereference(searchResponse);
    }

    @Override
    public SearchResponse apply(SearchResponse searchResponse) {
        return this.dereferenceResponse(searchResponse);
    }

    @Override
    public int hashCode()
    {
        return LdapUtils.computeHashCode(HASH_CODE_SEED);
    }

    @Override
    public String toString()
    {
        return new StringBuilder("[").append(getClass().getName()).append("@").append(hashCode()).append("]").toString();
    }
}
