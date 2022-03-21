package org.apereo.cas.deref;

import lombok.extern.slf4j.Slf4j;
import org.ldaptive.control.RequestControl;

import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.ldap.Control;
import javax.naming.ldap.LdapContext;

import org.springframework.ldap.control.AbstractRequestControlDirContextProcessor;

import java.util.HashMap;

@Slf4j
public class DereferenceRequestControl extends AbstractRequestControlDirContextProcessor implements RequestControl, Control {

    /** OID of this control. */
    public static final String OID = "1.3.6.1.4.1.4203.666.5.16";
    public boolean critical = false;
    public HashMap<String,String> dereference;

    /** Default constructor*/
    public DereferenceRequestControl() {
        super();
    }

    /**
     * Creates a new force update control.
     *
     * @param  critical  whether this control is critical
     */
    public DereferenceRequestControl(HashMap<String,String> hmap, boolean critical) {
        super();
        this.dereference = hmap;
        this.critical = critical;
    }

    @Override
    public Control createRequestControl() throws NullPointerException{
        Control ctrl=null;
        try {
            if( dereference!=null ) {
                ctrl = (Control) new DereferenceControl(dereference, critical);
            }
        }
        catch( Exception ex) {
            LOGGER.error("Exception raised while creating DerefControl",ex);
        }
        return ctrl;
    }

    @Override
    public boolean equals(final Object o)
    {
        if (o == this) {
            return true;
        }
        return o instanceof DereferenceControl && super.equals(o);
    }


    @Override
    public void postProcess(DirContext dirContext) throws NamingException { }

    /**
     * Get the existing RequestControls from the LdapContext,
     * call createRequestControll to get a new instance, build
     * a new array of Controls and set it on the LdapContext
     * @param ctx an LdapContext instance
     * @throws NamingException
     */
    @Override
    public void preProcess(DirContext ctx)
            throws NamingException
    {
        LdapContext ldapContext;

        if (ctx instanceof LdapContext)
        {
            ldapContext = (LdapContext) ctx;
        }
        else
        {
            throw new IllegalArgumentException("Request Control operations require LDAPv3 - " +
                    "Context must be of type LdapContext");
        }

        Control[] requestControls = ldapContext.getRequestControls();
        Control newControl = createRequestControl();
        if( newControl == null)
        {
            LOGGER.warn("DerefRequestControl couldn't be created. This error might not be fatal."
                    + "Normal -not dereferenced- user attributes may still be returned.");
            return;
        }

        Control[] newControls = new Control[requestControls.length + 1];
        for (int i = 0; i < requestControls.length; i++)
        {
            newControls[i] = requestControls[i];
        }

        // Add the new Control at the end of the array.
        newControls[requestControls.length]=newControl;

        ldapContext.setRequestControls(newControls);
    }

    @Override
    public String getOID() {
        return OID;
    }

    @Override
    public boolean getCriticality() {
        return critical;
    }

    @Override
    public byte[] encode() {
        return new byte[0];
    }

    @Override
    public boolean hasValue() {
        return false;
    }

    @Override
    public String getID() {
        return this.getID();
    }

    @Override
    public boolean isCritical() {
        return this.critical;
    }

    @Override
    public byte[] getEncodedValue() {
        return new byte[0];
    }
}
