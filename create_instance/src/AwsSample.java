import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;



import ch.ethz.ssh2.Connection;
import ch.ethz.ssh2.Session;
import ch.ethz.ssh2.StreamGobbler;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.PropertiesCredentials;
import com.amazonaws.services.ec2.model.KeyPair;
//import com.amazonaws.services.directconnect.model.Connection;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairResult;
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest;
import com.amazonaws.services.ec2.model.CreateTagsRequest;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.amazonaws.services.ec2.model.DescribeImagesResult;
import com.amazonaws.services.ec2.model.DescribeInstanceStatusRequest;
import com.amazonaws.services.ec2.model.DescribeInstanceStatusResult;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.DescribeKeyPairsResult;
import com.amazonaws.services.ec2.model.Image;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.InstanceState;
import com.amazonaws.services.ec2.model.InstanceStatus;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;
import com.amazonaws.services.ec2.model.StartInstancesRequest;
import com.amazonaws.services.ec2.model.StopInstancesRequest;
import com.amazonaws.services.ec2.model.Tag;
import com.amazonaws.services.ec2.model.TerminateInstancesRequest;






public class AwsSample {

    /*
     * Important: Be sure to fill in your AWS access credentials in the
     *            AwsCredentials.properties file before you try to run this
     *            sample.
     * http://aws.amazon.com/security-credentials
     */

    static AmazonEC2      ec2;

    static KeyPair keyPair;
    
    public static void main(String[] args) throws Exception {


    	 AWSCredentials credentials = new PropertiesCredentials(
    			 AwsSample.class.getResourceAsStream("AwsCredentials.properties"));

         /*********************************************
          * 
          *  #1 Create Amazon Client object
          *  
          *********************************************/
    	 System.out.println("#1 Create Amazon Client object");
         ec2 = new AmazonEC2Client(credentials);

         
       
        try {
        	
        	/*********************************************
        	 * 
             *  #2 Describe Availability Zones.
             *  
             *********************************************/
        	System.out.println("#2 Describe Availability Zones.");
            DescribeAvailabilityZonesResult availabilityZonesResult = ec2.describeAvailabilityZones();
            System.out.println("You have access to " + availabilityZonesResult.getAvailabilityZones().size() +
                    " Availability Zones.");

            /*********************************************
             * 
             *  #3 Describe Available Images
             *  
             *********************************************/
            /*
            System.out.println("#3 Describe Available Images");
            DescribeImagesResult dir = ec2.describeImages();
            List<Image> images = dir.getImages();
            System.out.println("You have " + images.size() + " Amazon images");
            
            */
            
            /*********************************************
             *                 
             *  #4 Describe Key Pair
             *                 
             *********************************************/
            System.out.println("#4 Describe Key Pair");
            DescribeKeyPairsResult dkr = ec2.describeKeyPairs();
            System.out.println(dkr.toString());
            
            /*********************************************
             * 
             *  #5 Describe Current Instances
             *  
             *********************************************/
            System.out.println("#5 Describe Current Instances");
            DescribeInstancesResult describeInstancesRequest = ec2.describeInstances();
            List<Reservation> reservations = describeInstancesRequest.getReservations();
            Set<Instance> instances = new HashSet<Instance>();
            // add all instances to a Set.
            for (Reservation reservation : reservations) {
            	instances.addAll(reservation.getInstances());
            }
            
            System.out.println("You have " + instances.size() + " Amazon EC2 instance(s).");
            for (Instance ins : instances){
            	
            	// instance id
            	String instanceId = ins.getInstanceId();
            	
            	// instance state
            	InstanceState is = ins.getState();
            	System.out.println(instanceId+" "+is.getName());
            }
            
            
            //Below Code is Added by Praveen 
            
            // Create Security Group for Instance
            
             String GroupName = "GrpAws8"; 
             CreateSecurityGroupRequest GroupRequest = new CreateSecurityGroupRequest(GroupName, "AWS2 group");
             ec2.createSecurityGroup(GroupRequest);
              AuthorizeSecurityGroupIngressRequest IngressRequest = new AuthorizeSecurityGroupIngressRequest();
              IngressRequest.setGroupName(GroupName);
           
            //Rule for Http
            //Allowing Every one to Access
            IpPermission HttpPerm = new IpPermission();
            HttpPerm.setIpProtocol("tcp");
            HttpPerm.setFromPort(80);
            HttpPerm.setToPort(80);
            List<String> ipAddr = new ArrayList<String>();
            ipAddr.add("0.0.0.0/0"); 
            HttpPerm.setIpRanges(ipAddr);
            
            //Rule for SSH
            //Allowing Every one to Access
            IpPermission SSHPerm = new IpPermission();
            SSHPerm.setIpProtocol("tcp");
            SSHPerm.setFromPort(22);
            SSHPerm.setToPort(22);
            List<String> ipRanges1 = new ArrayList<String>();
            ipRanges1.add("0.0.0.0/0"); 
            SSHPerm.setIpRanges(ipRanges1);
              
                       
            //Rule for TCP
            //Allowing Every one to Access
            IpPermission TCPPerm = new IpPermission();
            TCPPerm.setIpProtocol("tcp");
            TCPPerm.setFromPort(0);
            TCPPerm.setToPort(65535);
            List<String> ipRanges3 = new ArrayList<String>();
            ipRanges3.add("0.0.0.0/0"); 
            TCPPerm.setIpRanges(ipRanges3);
            
         
            // Rules added to the Ingress Request
            List<IpPermission> Rules = new ArrayList<IpPermission>();
            Rules.add(HttpPerm);
            Rules.add(SSHPerm);
            Rules.add(TCPPerm);
            IngressRequest.setIpPermissions(Rules);
            
            ec2.authorizeSecurityGroupIngress(IngressRequest);
            List<String> group_Name = new ArrayList<String>();
            group_Name.add(GroupName);
            
            
            
            // Key Pair Request         
            
            
            CreateKeyPairRequest KeyReq = new CreateKeyPairRequest();
            KeyReq.setKeyName("AWS_key8");
            CreateKeyPairResult keyRes = ec2.createKeyPair(KeyReq);
            
           
            keyPair = keyRes.getKeyPair();
            
            System.out.println("\n Name of the key = " + keyPair.getKeyName()+"\n ");
            		
            System.out.println("Public key =" + keyPair.getKeyFingerprint()+"\n ");
            		
            System.out.println("The Encrypted Key = \n" + keyPair.getKeyMaterial()+"\n");
           
            
            // Store the Key in .pem File
          
            		

            try {
            	 
    			String content = keyPair.getKeyMaterial();
     
    			 String fileName="C:\\Users\\Uchiha\\Downloads\\"+"AWS_KEY"+".pem"; 
    	         File Key_File = new File(fileName); 
     
    			// if file doesnt exists, then create it
    	         
    			if (!Key_File.exists()) {
    				Key_File.createNewFile();
    			}
     
    			FileWriter fw = new FileWriter(Key_File.getAbsoluteFile());
    			BufferedWriter bw = new BufferedWriter(fw);
    			bw.write(content);
    			bw.close();
     
    			System.out.println("Done");
     
    		} catch (IOException e) {
    			e.printStackTrace();
    		}
            
            // End of Code
            
          
            
            
            /*********************************************
             * 
             *  #6 Create an Instance
             *  
             *********************************************/
            
            System.out.println("#6 Create an Instance");
            String imageId = "ami-76f0061f"; //Basic 32-bit Amazon Linux AMI
            int minInstanceCount = 1; // create 1 instance
            int maxInstanceCount = 1;
            RunInstancesRequest rir = new RunInstancesRequest(imageId, minInstanceCount, maxInstanceCount);
            
            
            //code written by praveen
            // give the instance the key we just created
            rir.setKeyName("AWS_key8");
            
            // set the instance in the group we just created
            rir.setSecurityGroups(group_Name);
            
            RunInstancesResult result = ec2.runInstances(rir);
            
          
            
			
            
            //get instanceId from the result
            List<Instance> resultInstance = result.getReservation().getInstances();
            String createdInstanceId = null;
            String PublicDNSName="";
            
            
            for (Instance ins : resultInstance){
            	
            	
            	createdInstanceId = ins.getInstanceId();
            	
            	PublicDNSName = ins.getPublicIpAddress();
            	PublicDNSName = ins.getPrivateDnsName();
            	PublicDNSName = ins.getPrivateIpAddress();
            	PublicDNSName = ins.getPublicDnsName();
            	
            	System.out.println("New instance has been created: "+ins.getInstanceId());
            	
            	
            }
            
                   
           //waiting for instance to get into Initialise state
            DescribeInstanceStatusRequest describeInstanceRequest = new DescribeInstanceStatusRequest().withInstanceIds(createdInstanceId);
        	DescribeInstanceStatusResult describeInstanceResult = ec2.describeInstanceStatus(describeInstanceRequest);
        	List<InstanceStatus> state1 = describeInstanceResult.getInstanceStatuses();
        	while (state1.size() < 1) { 
        	    // Do nothing, just wait, have thread sleep if needed
        	    describeInstanceResult = ec2.describeInstanceStatus(describeInstanceRequest);
        	    state1 = describeInstanceResult.getInstanceStatuses();
        	    Thread.sleep(2000);
       	    
        	}
        	
            describeInstancesRequest = ec2.describeInstances();
            reservations = describeInstancesRequest.getReservations();
            
            // add all instances to a Set.
            for (Reservation reservation : reservations) {
            	instances.addAll(reservation.getInstances());
            }
            
            
            String InstanceIPAddr= null; 
            
            for (Instance instmp : instances){
            	
            	// instance id
            	String instanceId = instmp.getInstanceId();
            	if (instanceId.equals(createdInstanceId)){
            		InstanceIPAddr = instmp.getPublicIpAddress();
            	}
            }

        	System.out.println("\tPublic IP: "+ InstanceIPAddr);
            //end of code
           
            /*********************************************
             * 
             *  #7 Create a 'tag' for the new instance.
             *  
             *********************************************/
            System.out.println("#7 Create a 'tag' for the new instance.");
            List<String> resources = new LinkedList<String>();
            List<Tag> tags = new LinkedList<Tag>();
            Tag nameTag = new Tag("Name", "MyFirstInstance");
            
            resources.add(createdInstanceId);
            tags.add(nameTag);
            
            CreateTagsRequest ctr = new CreateTagsRequest(resources, tags);
            ec2.createTags(ctr);
            
            
                        
            /*********************************************
             * 
             *  #8 Stop/Start an Instance
             *  
             *********************************************/
            System.out.println("#8 Stop the Instance");
            List<String> instanceIds = new LinkedList<String>();
            instanceIds.add(createdInstanceId);
            
            //stop
            StopInstancesRequest stopIR = new StopInstancesRequest(instanceIds);
            //ec2.stopInstances(stopIR);
            
            //start
            StartInstancesRequest startIR = new StartInstancesRequest(instanceIds);
            //ec2.startInstances(startIR);
            
            
            /*********************************************
             * 
             *  #9 Terminate an Instance
             *  
             *********************************************/
            System.out.println("#9 Terminate the Instance");
            TerminateInstancesRequest tir = new TerminateInstancesRequest(instanceIds);
            //ec2.terminateInstances(tir);
            
                        
            /*********************************************
             *  
             *  #10 shutdown client object
             *  
             *********************************************/
            ec2.shutdown();
            
            ///SSH Programatically
            
            //Wait till the instance gets into Initialised State and then Assign the public ID To SSHAgent Class object.
            
            try
            {
            	Thread.sleep(90000);
                SSHAgent1 sshAgent = new SSHAgent1(InstanceIPAddr, "ec2-user", "password" );
                if( sshAgent.connect() ) 
                {
                	 String Info = sshAgent.executeCommand( "df -k" );
                     System.out.println( "\n Information of Disk: " + Info );
                     
                     String WHO = sshAgent.executeCommand( "whoami" );
                     System.out.println( "\n My username for System: " + WHO );
                    
                    
                    // Logout
                    sshAgent.logout();
                }
            }
            catch( Exception e )
            {
                e.printStackTrace();
            }
         
            
            
        } catch (AmazonServiceException ase) {
                System.out.println("Caught Exception: " + ase.getMessage());
                System.out.println("Reponse Status Code: " + ase.getStatusCode());
                System.out.println("Error Code: " + ase.getErrorCode());
                System.out.println("Request ID: " + ase.getRequestId());
        }

        
    }
}
class SSHAgent1 {
    
    /**
     * The hostname (or IP address) of the server to connect to
     */
    private String hostname;
    
    /**
     * The username of the user on that server
     */
    private String username;
    
    /**
     * The password of the user on that server
     */
    private String password;
    
    /**
     * A connection to the server
     */
    private Connection connection;
    
    /**
     * Creates a new SSHAgent
     * 
     * @param hostname
     * @param username
     * @param password
     */
    public SSHAgent1( String hostname, String username, String password )
    {
        this.hostname = hostname;
        this.username = username;
        this.password = password;
    }
    
    /**
     * Connects to the server
     * 
     * @return        True if the connection succeeded, false otherwise
     */
    public boolean connect() throws Exception
    {
        try
        {
            // Connect to the server
            connection = new Connection( hostname );
            connection.connect();
            
            // Authenticate
            
            File file = new File("C:\\Users\\Uchiha\\Downloads\\AWS_KEY.pem");
            
            boolean result = connection.authenticateWithPublicKey(username, file, password);
            System.out.println( "Connection result: " + result );
            return result;
        }
        catch( Exception e )
        {
            throw new Exception( "An exception occurred while trying to connect to the host: " + hostname + ", Exception=" + e.getMessage(), e ); 
        }
    }
    
    /**
     * Executes the specified command and returns the response from the server
     *  
     * @param command        The command to execute
     * @return               The response that is returned from the server (or null)
     */
    public String executeCommand( String command ) throws Exception 
    {
        try
        {
            // Open a session
            Session session = connection.openSession();
            
            // Execute the command
            session.execCommand( command );
            
            // Read the results
            StringBuilder sb = new StringBuilder();
            InputStream stdout = new StreamGobbler( session.getStdout() );
            BufferedReader br = new BufferedReader(new InputStreamReader(stdout));
            String line = br.readLine();
            while( line != null )
            {
                sb.append( line + "\n" );
                line = br.readLine();
            }

            // DEBUG: dump the exit code
            System.out.println( "ExitCode: " + session.getExitStatus() );

            // Close the session
            session.close();
            
            // Return the results to the caller
            return sb.toString();
        }
        catch( Exception e )
        {
            throw new Exception( "An exception occurred while executing the following command: " + command + ". Exception = " + e.getMessage(), e );
        }
    }

    /**
     * Logs out from the server
     * @throws Exception
     */
    public void logout() throws Exception
    {
        try
        {
            connection.close();
        }
        catch( Exception e )
        {
            throw new Exception( "An exception occurred while closing the SSH connection: " + e.getMessage(), e );
        }
    }
    
    /**
     * Returns true if the underlying authentication is complete, otherwise returns false
     * @return
     */
    public boolean isAuthenticationComplete()
    {
        return connection.isAuthenticationComplete();
    }
    
  }



 