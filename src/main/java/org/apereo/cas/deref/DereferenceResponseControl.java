package org.apereo.cas.deref;

import com.sun.jndi.ldap.Ber;
import com.sun.jndi.ldap.BerDecoder;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.ObjectUtils;
import org.ldaptive.LdapAttribute;
import org.ldaptive.SearchResponse;
import org.ldaptive.asn1.DERBuffer;
import org.ldaptive.control.ResponseControl;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.ldap.Control;
import javax.naming.ldap.HasControls;
import java.io.ByteArrayOutputStream;
import java.util.*;

@Slf4j
public class DereferenceResponseControl implements ResponseControl {

    public static final String OID = "1.3.6.1.4.1.4203.666.5.16";
    private static final int LBER_SEQUENCE = 48;
    private static final int LBER_SET = 49;
    private ArrayList<String> dereferenceAttributeName;
    private ArrayList<String> dereferenceAttributeValue;
    private SearchResponse entry;
    private Control responseCtrl;
    private byte[] berVal;
    private Map<String,ArrayList<Object>> dereferenceAttrs;

    private HashMap<String,String> dereferenceExtended =null;

    /**
     * Decodes the ber encoded returned data. The data format is:
     * <pre>
     * {{derefAttrName,derefAttrVal{{attr1{val1}}{attr2{val2}}...}}}
     * </pre>
     * @param sr the search operation result
     * @throws NamingException
     */
    public DereferenceResponseControl(SearchResponse sr)
            throws NamingException
    {
        entry = sr;
        responseCtrl = null;
        //dereferenceExtended=extended_attrs;

        if (entry.getControls() != null)
        {
            Control[] response_controls = ((HasControls)entry).getControls();
            for (int i = 0; i < response_controls.length; i++)
            {
                if( OID.equalsIgnoreCase(response_controls[i].getID()))
                    responseCtrl = response_controls[i];
            }
        }

        dereferenceAttrs = new HashMap<String,ArrayList<Object>>();
        if( responseCtrl != null )
        {
            dereferenceAttributeName = new ArrayList();
            dereferenceAttributeValue = new ArrayList();

            berVal = responseCtrl.getEncodedValue();
            BerDecoder ber = new BerDecoder(berVal, 0, berVal.length); //:buffer,offset,bufSize

            if( LOGGER.isDebugEnabled() )
            {
                ByteArrayOutputStream outStream = new ByteArrayOutputStream();
                Ber.dumpBER(outStream," ",berVal,0,berVal.length);
                LOGGER.trace("Response ber encoded buffer contents:" + outStream.toString());
            }

            parse_response(ber);
        }
        else
        {
            //respCtrl is null, set everything to null
            berVal = null;
        }
        LOGGER.trace("Got dereference data: " + dereferenceAttrs.toString());
    }

    /**
     * Gather and return the normal attributes contained within the response.
     * @return map of (string,list(object)) containing (name,value) pairs
     */
    public Map getAttrs()
    {
        Map<String,ArrayList<Object>> attrs = new HashMap<String,ArrayList<Object>>();

        try
        {
            for(Collection<LdapAttribute> e = entry.getEntry().getAttributes(); !e.isEmpty();  )
            {
                Attribute attr = (Attribute)e;
                attrs.put(attr.getID(), Collections.list((Enumeration<Object>)attr.getAll()));
                //the cast is kinda horrible, but it is needed
            }
        }
        catch(Exception ex)
        {
            attrs=null;
            LOGGER.error("Error parsing naming enumeration results.",ex);
        }

        return attrs;
    }

    @Override
    public int hashCode() {
        return 0;
    }

    public ArrayList<String> getDereferenceAttributeName() {
        return dereferenceAttributeName;
    }

    public void setDereferenceAttributeName(ArrayList<String> dereferenceAttributeName) {
        this.dereferenceAttributeName = dereferenceAttributeName;
    }

    public ArrayList<String> getDereferenceAttributeValue() {
        return dereferenceAttributeValue;
    }

    public void setDereferenceAttributeValue(ArrayList<String> dereferenceAttributeValue) {
        this.dereferenceAttributeValue = dereferenceAttributeValue;
    }

    public SearchResponse getEntry() {
        return entry;
    }

    public void setEntry(SearchResponse entry) {
        this.entry = entry;
    }

    public Control getResponseCtrl() {
        return responseCtrl;
    }

    public void setResponseCtrl(Control responseCtrl) {
        this.responseCtrl = responseCtrl;
    }

    public byte[] getBerVal() {
        return berVal;
    }

    public void setBerVal(byte[] berVal) {
        this.berVal = berVal;
    }

    public Map<String, ArrayList<Object>> getDereferenceAttrs() {
        return dereferenceAttrs;
    }

    public void setDereferenceAttrs(Map<String, ArrayList<Object>> dereferenceAttrs) {
        this.dereferenceAttrs = dereferenceAttrs;
    }

    public HashMap<String, String> getDereferenceExtended() {
        return dereferenceExtended;
    }

    public void setDereferenceExtended(HashMap<String, String> dereferenceExtended) {
        this.dereferenceExtended = dereferenceExtended;
    }


    @Override
    public void decode(DERBuffer encoded) {

    }


    /*
     * Private Utility Methods
     */

    /*
     * Returns true if the derefedAttrName is set for derefAttrName in extended
     * @param extended syntax: derefAttrName:derefedAttrName1,derefedAttrName2;...
     * @param derefAttrName see extended syntax 1 line above
     * @param derefedAttrName see extended syntax 2 lines above
     * @return boolean
     */
    private Boolean is_extended(HashMap<String,String> extended, String derefAttrName, String derefedAttrName)
    {
        if(extended == null)
            return false;

        for( Map.Entry<String,String> e : extended.entrySet() )
        {
            if( derefAttrName.equalsIgnoreCase(e.getKey()) )
            {
                String[] tmpAttrs = e.getValue().split(",");
                for( int j=0 ; j< tmpAttrs.length ; j++)
                {
                    if( derefedAttrName.equalsIgnoreCase(tmpAttrs[j]) )
                    {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /*
     * Adds an attribute value to the dereference attribute list.
     * @param name the attribute name
     * @param value the attribute value
     * @param extended use extended notation as well as normal, or not.
     * @return void
     */
    private void add_deref_value(String name, String value, boolean extended)
    {
        ArrayList<Object> attrList = dereferenceAttrs.get(name);
        if( attrList == null )
            attrList = new ArrayList<Object>();

        attrList.add(value);
        dereferenceAttrs.put(name, attrList);
    }

    /*
     * Parse the dereference ber response sent from the ldap server.
     * @param b ber buffer object, initialized from the ldap ber response
     * @return void
     */
    private void parse_response(BerDecoder b)
    {
        /*
         * The package com.sun.jndi.ldap.Ber, follows the ASN.1 standard for
         * identifier octets, available here:
         * http://en.wikipedia.org/wiki/Basic_Encoding_Rules#Identifier_octets
         *
         * OpenLDAP is using the following tags though (taken from lber.h):
         * #define LBER_BOOLEAN		((ber_tag_t) 0x01UL)
         * #define LBER_INTEGER		((ber_tag_t) 0x02UL)
         * #define LBER_BITSTRING       ((ber_tag_t) 0x03UL)
         * #define LBER_OCTETSTRING	((ber_tag_t) 0x04UL)
         * #define LBER_NULL		((ber_tag_t) 0x05UL)
         * #define LBER_ENUMERATED	((ber_tag_t) 0x0aUL)
         * #define LBER_SEQUENCE	((ber_tag_t) 0x30UL)	// constructed
         * #define LBER_SET		((ber_tag_t) 0x31UL)	// constructed
         *
         * The actual difference lies with the sequence and set tags, which
         * are 16, 17 for the standard and 48, 49 for openldap respectively.
         * (in decimal representetaion)
         */

        int[] seqlen = new int[1];
        int attrList_length, attrList_startingPosition;
        String curDerefAttrName, curDerefAttrVal, attrName, attrVal;

        try
        {
            b.parseSeq(seqlen);
            LOGGER.trace("1:\tsequence of length: " + Arrays.toString(seqlen));
            while( b.bytesLeft() > 0)
            {
                b.parseSeq(seqlen);
                LOGGER.trace("2:\t\tsequence of length: " + Arrays.toString(seqlen));
                curDerefAttrName = b.parseString(true); //true: decode utf8
                curDerefAttrVal = b.parseString(true);
                LOGGER.trace("2:\t\tderefAttribute: " + curDerefAttrName + "=" + curDerefAttrVal);

                /*
                check and possibly consume tag number for optional,
                context-specific primitive 0 ([0], check also the relevant draft)
                */
                if( b.peekByte() != 160)
                {
                    LOGGER.trace("2:\t\tNo results found for previous argument.");
                    continue;
                }
                b.parseByte(); //0xA0U
                attrList_length = b.parseByte(); //length of the optional following attributeList

                attrList_startingPosition = b.getParsePosition();
                while( b.getParsePosition() < attrList_startingPosition + attrList_length )
                {
                    b.parseSeq(seqlen);
                    LOGGER.trace("3:\t\t\tsequence of length: " + Arrays.toString(seqlen));

                    attrName = b.parseString(true);
                    LOGGER.trace("3:\t\t\tattrName: " + attrName);

                    b.parseSeq(seqlen);
                    LOGGER.trace("3:\t\t\tset of length: " + Arrays.toString(seqlen));

                    while( b.peekByte() == Ber.ASN_SIMPLE_STRING )
                    {
                        attrVal = b.parseString(true);
                        LOGGER.trace("3:\t\t\tattrVal: " + attrVal);

                        add_deref_value(curDerefAttrName+"."+attrName, attrVal, false);
                        if( is_extended(dereferenceExtended, curDerefAttrName, attrName) )
                        {
                            add_deref_value(curDerefAttrName+"."+attrName+".extended",
                                    curDerefAttrVal+";"+attrVal,true);
                        }

                        if( b.bytesLeft() == 0 )
                            break;
                    }
                }
            }
        }
        catch( Exception ex)
        {
            LOGGER.error("(test) Ber decoding error occured at position: "
                    +b.getParsePosition()+" .",ex);
        }
    }


    @Override
    public String getOID() {
        return null;
    }

    @Override
    public boolean getCriticality() {
        return false;
    }

}
