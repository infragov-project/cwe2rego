#
## Cookbook Name:: aligent-magento-dev
## Recipe:: restore-database
##
## Copyright 2015, Aligent Consulting
##
## Permission is hereby granted, free of charge, to any person obtaining
## a copy of this software and associated documentation files (the
## "Software"), to deal in the Software without restriction, including
## without limitation the rights to use, copy, modify, merge, publish,
## distribute, sublicense, and/or sell copies of the Software, and to
## permit persons to whom the Software is furnished to do so, subject to
## the following conditions:
##
## The above copyright notice and this permission notice shall be
## included in all copies or substantial portions of the Software.
##
## THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
## EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
## MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
## NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
## LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
## OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
## WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
##
#

flag_file="#{node['app']['document_root']}/.databaseRestored"

if !File.exists?(flag_file)

    s3_file "/tmp/backup.tar.gz" do
        remote_path node['app']['s3_backup']['remote_filename']
        bucket node['app']['s3_backup']['bucket']
        aws_access_key_id node['app']['s3_backup']['aws_access_key']
        aws_secret_access_key node['app']['s3_backup']['aws_secret_access_key']
        owner node['app']['primary_user']
        group node['app']['primary_user']
        mode "0644"
        action :create
    end

    bash 'extract_and_restore_db' do
      cwd node['app']['document_root']
      code <<-EOH
        RESTORE_PATH=/tmp/restore

        # Ensure restore temp folder exists and unpack backup file into it.
        if [ ! -d $RESTORE_PATH ]; then
            mkdir $RESTORE_PATH
        fi
        pushd $RESTORE_PATH

        echo "Unpacking tarball..."
        tar zxvf ../backup.tar.gz --strip-components=2 > /dev/null

        popd  # Return to Magento root

        # Ensure media folder exists
        if [ ! -d ./media ]; then
            mkdir ./media
            chown #{node['app']['primary_user']}:apache ./media
            chmod -R 777 ./media
        fi

        echo "Copying media..."
        cp -a ${RESTORE_PATH}/files/assets/* ./media

        echo "Dropping and recreating DB..."
        ./util/n98-magerun.phar db:drop -f
        ./util/n98-magerun.phar db:create

        echo "Restoring main database file..."
        ./util/n98-magerun.phar db:console < ${RESTORE_PATH}/#{node['app']['s3_backup']['db_file_name']}

        echo "Restoring database config table..."
        ./util/n98-magerun.phar db:console < ${RESTORE_PATH}/#{node['app']['s3_backup']['db_config_file_name']}

        echo "Cleaning up..."
        rm -rf $RESTORE_PATH
        rm /tmp/backup.tar.gz

        EOH
    end

    execute "dev_config_script" do
        command "./util/dev-config.sh"
        cwd node['app']['document_root']
    end

    file flag_file do
        content 'Delete this file and run "vagrant provision" on your home machine to update your database.'
        mode '0755'
        owner node['app']['primary_user']
        group node['app']['primary_user']
        action :create_if_missing
    end

end
