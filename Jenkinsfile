#!/usr/bin/env groovy

def targetBucket = "${env.CI_BUCKET}"
def projectName = 'zippie-vault'
def hostTempDir = "${projectName}_${env.BUILD_ID}"

// Slack integration
def notifySlack (color, state) {
  def channel = '#cibot'

  slackSend(
    channel: "${channel}",
    color: "${color}",
    message: "${state}: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]' ${env.BUILD_URL}"
  )

}

properties(
  [parameters(
    [string(
      defaultValue: "${env.CI_BUCKET}", 
      description: 'Specify the target s3 bucket where built artifacts are to be stored. Syntax: s3://bucketname', 
      name: 'targetBucket', 
      trim: true
    ),
    string(
      defaultValue: "${projectName}",
      description: 'Specify the target path within the bucket where built artifacts are to be stored.',
      name: 'targetPath', 
      trim: true
    )]
  )]
)

node {

  try {
    stage ('prebuild environment prep and cleanup') {
      sh "rm -rf /tmp/${hostTempDir}"
      sh "mkdir /tmp/${hostTempDir}"
    }

    stage ('checkout project sources') {
      checkout([
        $class: 'GitSCM',
        branches: scm.branches,
        doGenerateSubmoduleConfigurations: scm.doGenerateSubmoduleConfigurations,
        extensions: scm.extensions + [[$class: 'CloneOption', noTags: false, shallow: false, reference: '']],
        submoduleCfg: [],
        userRemoteConfigs: scm.userRemoteConfigs
      ])
    }

    // Gather and clean up variables for the artifact generation
    def shortCommit = sh(returnStdout: true, script: 'git rev-parse --short=8 HEAD').trim()
    def descCommit = sh(returnStdout: true, script: 'git describe --tags').trim()
    def sanitize = $/echo ${env.BRANCH_NAME} | sed 's/\//\_/'/$
    def sanitizedBranchName = sh(returnStdout: true, script: sanitize).trim()
    def pkgName = "${projectName}_${sanitizedBranchName}-${descCommit}_${env.BUILD_ID}"

    stage ('docker nodejs build and package') {
      nodeImage = docker.build('zippie/nodejs', '-f Dockerfile .' )
      nodeImage.inside("--volume=/tmp/$hostTempDir/:/tmp") {
        sh "mkdir -p /tmp/app"
        sh "echo ${sanitizedBranchName}-${env.BUILD_ID}-${shortCommit} > /tmp/app/version.txt"
        sh "tar cf /tmp/${pkgName}.tar /app/dist"
        sh "tar -C /tmp --append --file=/tmp/${pkgName}.tar app/version.txt"
        sh "gzip /tmp/${pkgName}.tar"
        sh "mv /tmp/${pkgName}.tar.gz /tmp/${pkgName}.tgz"
        sh "mv /tmp/app/version.txt /tmp/latest-${sanitizedBranchName}"
      }
    }

    stage ('upload artifact') {
      sh "aws s3 cp /tmp/${hostTempDir}/${pkgName}.tgz ${targetBucket}/${targetPath}/"
      sh "aws s3 cp /tmp/${hostTempDir}/latest-${sanitizedBranchName} ${targetBucket}/${targetPath}/"
    }

    stage ("publish artifact") {
      sh "cd /tmp/${hostTempDir} && tar xvfz /tmp/${hostTempDir}/${pkgName}.tgz"
      sh "cd /tmp/${hostTempDir}/app/dist && aws s3 sync --delete . s3://z-dev-vault/public/"
    }

    stage ("cleanup") {
      sh "rm -rf /tmp/${hostTempDir}"
    }

    notifySlack('#7CFC00', 'SUCCESS')

  } catch(err) {
    echo "Caught ${err}"
    currentBuild.result = 'FAILURE'
    notifySlack('#FF0000', 'FAILURE')
  }
}
