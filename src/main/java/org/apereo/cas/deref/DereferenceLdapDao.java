package org.apereo.cas.deref;

import lombok.extern.slf4j.Slf4j;
import org.apereo.services.persondir.IPersonAttributes;
import org.apereo.services.persondir.support.AbstractQueryPersonAttributeDao;
import org.apereo.services.persondir.support.CaseInsensitiveAttributeNamedPersonImpl;
import org.apereo.services.persondir.support.CaseInsensitiveNamedPersonImpl;
import org.apereo.services.persondir.support.QueryType;
import org.ldaptive.*;
import org.ldaptive.handler.LdapEntryHandler;
import org.ldaptive.handler.SearchResultHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

import javax.naming.directory.SearchControls;
import java.time.Duration;
import java.util.*;

@Slf4j
public class DereferenceLdapDao extends AbstractQueryPersonAttributeDao<FilterTemplate> implements InitializingBean {

    private final boolean setReturningAttributes = true;
    private QueryType queryType = QueryType.AND;
    private HashMap<String, String> dereference = null;
    private HashMap<String, String> dereferenceExtended = null;

    private SearchControls SearchCtrl;
    private DereferenceResponseControl dereferenceResponseControl;
    private DereferenceResultHandler dereferenceResultHandler;
    private DereferenceRequestControl dereferenceRequestControl;
    private DereferenceResponseControlHandler dereferenceResponseControlHandler;

    private boolean useDeref = true; //defaults to true

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    /**
     * Search base DN.
     */
    private String baseDN;

    /**
     * Search controls.
     */
    private SearchControls searchControls;

    /**
     * LDAP connection factory.
     */
    private ConnectionFactory connectionFactory;

    /**
     * LDAP search filter.
     */
    private String searchFilter;

    /**
     * LDAP binary attributes.
     */
    private String[] binaryAttributes;

    /**
     * LDAP entry handlers.
     */
    private LdapEntryHandler[] entryHandlers;

    /**
     * LDAP search result handlers.
     */
    private SearchResultHandler[] searchResultHandlers;

    public DereferenceLdapDao() {
        super();
    }

    public String getBaseDN() {
        return baseDN;
    }

    /**
     * Sets the base DN of the LDAP search for attributes.
     *
     * @param dn LDAP base DN of search.
     */
    public void setBaseDN(final String dn) {
        if (dn == null) {
            this.baseDN = "";
        }

        this.baseDN = dn;
    }

    public void setDereference(HashMap<String, String> dereference) {
        this.dereference = dereference;
    }

    /**
     * @return Search controls to use for LDAP queries
     */
    public SearchControls getSearchControls() {
        return this.searchControls;
    }

    /**
     * Sets the LDAP search filter used to query for person attributes.
     *
     * @param filter Search filter of the form "(usernameAttribute={0})" where {0} and similar ordinal placeholders
     *               are replaced with query parameters.
     */
    public void setSearchFilter(final String filter) {
        this.searchFilter = filter;
    }

    /**
     * Sets a number of parameters that control LDAP search semantics including search scope,
     * maximum number of results retrieved, and search timeout.
     *
     * @param searchControls LDAP search controls.
     */
    public void setSearchControls(final SearchControls searchControls) {
        Assert.notNull(searchControls, "searchControls can not be null");
        this.searchControls = searchControls;
    }

    /**
     * Sets the connection factory that produces LDAP connections on which searches occur. It is strongly recommended
     * that this be a <code>PooledConnecitonFactory</code> object.
     *
     * @param connectionFactory LDAP connection factory.
     */
    public void setConnectionFactory(final ConnectionFactory connectionFactory) {
        this.connectionFactory = connectionFactory;
    }

    /**
     * Sets binary attributes.
     *
     * @param binaryAttributes array.
     */
    public void setBinaryAttributes(final String[] binaryAttributes) {
        this.binaryAttributes = binaryAttributes;
    }

    /**
     * Sets entry handlers.
     *
     * @param handlers for LDAP entries.
     */
    public void setEntryHandlers(final LdapEntryHandler[] handlers) {
        this.entryHandlers = handlers;
    }

    /**
     * Sets search result handlers.
     *
     * @param handlers for LDAP search results.
     */
    public void setSearchResultHandlers(final SearchResultHandler[] handlers) {
        this.searchResultHandlers = handlers;
    }


    @Override
    protected List<IPersonAttributes> getPeopleForQuery(FilterTemplate filter, String userName) {
        SearchResponse response = null;
        dereferenceResultHandler = new DereferenceResultHandler();

        try{
            //todo: check supported controls with search query
            var search = new SearchOperation(this.connectionFactory);
            search.setEntryHandlers(entryHandlers);
            search.setSearchResultHandlers(dereferenceResultHandler);
            search.setControlHandlers(dereferenceResponseControlHandler);
            response = search.execute(createRequest(filter));

        }catch(Exception e){
            LOGGER.error("Error while searching. Check for misconfiguration issues!!!");
        }

        List<IPersonAttributes> peopleAttributes = new ArrayList<>(response.entrySize());
        for (var entry : response.getEntries()) {
            final IPersonAttributes person;
            var userNameAttribute = this.getConfiguredUserNameAttribute();
            var attributes = convertLdapEntryToMap(entry);
            if (response.getDiagnosticMessage() != null && !response.getDiagnosticMessage().isEmpty()) {
                var values = new ArrayList<>();
                values.add(response.getDiagnosticMessage());
                attributes.put("diagnosticMessage", values);
            }
            if (response.getMatchedDN() != null && !response.getMatchedDN().isEmpty()) {
                var values = new ArrayList<>();
                values.add(response.getMatchedDN());
                attributes.put("matchedDN", values);
            }

            if (attributes.containsKey(userNameAttribute)) {
                person = new CaseInsensitiveAttributeNamedPersonImpl(userNameAttribute, attributes);
            } else {
                person = new CaseInsensitiveNamedPersonImpl(userName, attributes);
            }
            peopleAttributes.add(person);
        }

        return peopleAttributes;
    }

    @Override
    protected FilterTemplate appendAttributeToQuery(final FilterTemplate filter, final String attribute, final List<Object> values) {
        final FilterTemplate query;
        if (filter == null) {
            query = new FilterTemplate(this.searchFilter);
        } else {
            query = filter;
        }

        if (this.isUseAllQueryAttributes() &&
                values.size() > 1 && (this.searchFilter.contains("{0}") || this.searchFilter.contains("{user}"))) {
            logger.warn("Query value will be indeterminate due to multiple attributes and no username indicator. Use attribute [{}] in query instead of {0} or {user}",
                    attribute);
        }

        if (values.size() > 0) {
            if (this.searchFilter.contains("{0}")) {
                query.setParameter(0, values.get(0).toString());
            } else if (this.searchFilter.contains("{user}")) {
                query.setParameter("user", values.get(0).toString());
            } else if (this.searchFilter.contains("{" + attribute + "}")) {
                query.setParameter(attribute, values.get(0).toString());
            }
            logger.debug("Constructed LDAP search query [{}]", query.format());
        }
        return query;
    }

    @Override
    public void afterPropertiesSet() throws Exception {

        SearchCtrl = this.getSearchControls();

        //DereferenceRequestControl dereferenceRequestControl;
        if(!useDeref)
        {
            LOGGER.info("Dereference disabled on request. Will use secondary search.");

            //Set up request controls
            dereferenceRequestControl = new DereferenceRequestControl(null, false);
            dereferenceResponseControlHandler = new DereferenceResponseControlHandler();
        }
        else
        {
            //Set up request controls
            dereferenceRequestControl = new DereferenceRequestControl(dereference, false);
            dereferenceResponseControlHandler = new DereferenceResponseControlHandler();

            if( dereference == null )
            {
                LOGGER.warn("Dereference related attributes were not set."
                        + "Dereference capabillities will not be used");
            }
        }

        if( dereference != null && dereferenceExtended != null) {//Check for correct values set in the extended deref
            for( Map.Entry<String,String> extendedEntry : dereferenceExtended.entrySet() ) {
                for( Map.Entry<String,String> derefEntry : dereference.entrySet() ) {
                    for( String extendedAttr : extendedEntry.getValue().split(",") ) {
                        if( extendedEntry.getKey().equalsIgnoreCase(derefEntry.getKey()) ) {
                            if( ! Arrays.asList((String[]) derefEntry.getValue().split(",")).contains(extendedAttr) ) {

                                LOGGER.warn("Requested extended attribute: " + extendedAttr +
                                        " not among the requested dereferenced attributes: " +
                                        derefEntry.getValue() +
                                        " .It will be ignored");
                            }
                        }
                    }
                }
            }
        }
    }

    /**
     * Creates a search request from a search filter.
     *
     * @param filter LDAP search filter.
     * @return ldaptive search request.
     */
    protected SearchRequest createRequest(final FilterTemplate filter) {
        var request = new SearchRequest();
        request.setBaseDn(filter.getParameters().values().toString());   //set parameters to search in dereferenced value's dn
        request.setFilter(filter);
        request.setBinaryAttributes(binaryAttributes);
        request.setControls(dereferenceRequestControl);

        /** LDAP attributes to fetch from search results. */
        if (getResultAttributeMapping() != null && !getResultAttributeMapping().isEmpty()) {
            var attributes = getResultAttributeMapping().keySet().toArray(new String[getResultAttributeMapping().size()]);
            request.setReturnAttributes(attributes);
        } else if (searchControls.getReturningAttributes() != null && searchControls.getReturningAttributes().length > 0) {
            request.setReturnAttributes(searchControls.getReturningAttributes());
        } else {
            request.setReturnAttributes(ReturnAttributes.ALL_USER.value());
        }

        var searchScope = SearchScope.SUBTREE;
        for (var scope : SearchScope.values()) {
            if (scope.ordinal() == this.searchControls.getSearchScope()) {
                searchScope = scope;
            }
        }
        request.setSearchScope(searchScope);
        request.setSizeLimit(Long.valueOf(this.searchControls.getCountLimit()).intValue());
        request.setTimeLimit(Duration.ofSeconds(searchControls.getTimeLimit()));
        return request;
    }

    protected Map<String, List<Object>> convertLdapEntryToMap(final LdapEntry entry) {
        if (entry.getAttribute("userAccountControl") != null) {
            var uac = Integer.parseInt(entry.getAttribute("userAccountControl").getStringValue());

        }
        final Map<String, List<Object>> attributeMap = new LinkedHashMap<>(entry.size());
        for (var attr : entry.getAttributes()) {
            attributeMap.put(attr.getName(), new ArrayList<>(attr.getStringValues()));
        }
        logger.debug("Converted ldap DN entry [{}] to attribute map {}", entry.getDn(), attributeMap);
        return attributeMap;
    }

}
